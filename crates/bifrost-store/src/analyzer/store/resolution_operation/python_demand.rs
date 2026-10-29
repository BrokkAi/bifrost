//! Dormant Python source rules. Environment containers describe imports; they
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
//! sys.modules[__name__] has only an expression slot; mutations through it are
//! not recognized as structural module receivers here (#7361). Direct attribute
//! writes through that expression currently lack this per-module safeguard.
//! A module object passed as a value and mutated through a parameter, attribute,
//! call result or other non-structural receiver is likewise a known hole in the
//! per-read proof. Retained reflective operations of these forms contribute one
//! python_dynamic_receiver_mutation_open reverse query obligation. Forms with
//! no retained mutation operation cannot contribute to that operation count.
//! Forward definitions expose neither this obligation nor python_environment_open
//! yet; their query-obligation channel is tracked by #7362.
pub(super) mod super_context;

use super::demand_closure::*;
use super::python_lexical::{self, PythonBindingProfile, PythonBindingProofs, PythonLexical};
use super::*;
use crate::analyzer::resolution::temporal_binding::{SessionBudget, Stop};
use crate::analyzer::resolution::{DemandReferenceKey, EndpointSignature, ResolutionAnswer};
use crate::analyzer::store::python_binding_rows::{BindingEvent, PythonBindingRows};
use crate::analyzer::store::selected_read_memo::RequestReadCache;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind;

type SuperContextRows =
    RequestReadCache<(i64, Option<u32>), Option<super_context::SuperContextRow>>;
type MemberRoleRows = RequestReadCache<(i64, u32), Option<(u32, Option<u32>, u32)>>;

const PYTHON_HALF_PLACEMENTS: &str = "SELECT providers.container_path
             FROM main.python_unit_summary_providers providers
             JOIN main.resolution_unit_summary_members members
               ON members.summary_id=providers.summary_id
              AND members.member_ordinal=providers.member_ordinal
             JOIN temp.selected_resolution_mounts mounted
               ON mounted.blob_id=members.blob_id AND mounted.persisted_relative_path=members.rel_path
             WHERE providers.summary_id=?1 AND mounted.mount_ordinal=?2
               AND providers.state IN ('selected','alternative')";

/// Survivors receive a cohort only after temporal reduction. Origin and source
/// byte position are deliberately absent from the ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PythonRank {
    pub cohort: u32,
}

/// A selected environment's identity is request-owned. The caller validates its
/// snapshot, profile and output digest before constructing the rules.
pub(super) struct PythonRules<'a, 'store, 'input> {
    pub ready: &'a ReadySelectedResolution<'store, 'input>,
    pub summary: i64,
    pub profile: PythonBindingProfile,
    /// Declared minimum Python version, not an exact interpreter version. None means undeclared.
    pub python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    pub cancellation: &'a CancellationToken,
    pub session: &'a ResolutionSession,
    pub observations: &'a RefCell<Vec<String>>,
    arena: &'a RefCell<ClosedRelations>,
    // One suspended source close owns these inputs. Remove them at publication;
    // rebuilding its borrowed Half view must perform no context/prefix SQL.
    source_inputs: RefCell<HashMap<CandidatePathIdentity, PythonHalfInputs>>,
    // One forward operation fixes the store and format; only blob selects rows.
    binding_rows: RefCell<RequestReadCache<i64, std::sync::Arc<PythonBindingRows>>>,
    // This forward operation fixes the summary, store and format; the placement
    // memo lives for the operation, so its key carries no epoch.
    placement_unit: [u8; 32],
    placements: RefCell<super::placement_access::PlacementMemo<String>>,
    root_prefixes: RefCell<RequestReadCache<i64, Vec<PythonRootPrefix>>>,
    module_sites: RefCell<RequestReadCache<i64, Option<ResolutionSiteId>>>,
    // Immutable selected-environment inputs are shared by all source halves
    // in this forward operation and dropped with the request.
    conditional_import_sites: RefCell<RequestReadCache<(i64, String), Vec<u32>>>,
    pub(super) super_context_rows: RefCell<SuperContextRows>,
    pub(super) member_role_rows: RefCell<MemberRoleRows>,
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
    pub(super) attribute_mutations:
        RefCell<HashMap<(SemanticId, SemanticId), ResolutionCompletion>>,
    pub(super) attribute_metaclasses:
        RefCell<HashMap<(SemanticId, SemanticId), ResolutionCompletion>>,
    prepared_references: RefCell<HashMap<CandidatePathIdentity, SemanticId>>,
    universe_mutations: RefCell<HashMap<CandidatePathIdentity, UniverseMutationInputs>>,
    module_mutations: RefCell<HashMap<CandidatePathIdentity, UniverseMutationInputs>>,
    deferred_mutations: RefCell<
        HashMap<CandidatePathIdentity, Vec<super::python_members::operations::ModuleMutation>>,
    >,
    // One query result, bounded by the selected environment's operation count.
    // Only can_write is per read; retain the inventory for this rules object's
    // query lifetime so identical alias walks do not charge the budget again.
    structural_mutations:
        RefCell<Option<Vec<super::python_members::operations::StructuralMutation>>>,
    // One selected inventory per space for this query. Each vector indexes at
    // most the environment's operation count; nothing survives PythonRules.
    pub(super) structural_spaces: RefCell<HashMap<Option<SemanticId>, Vec<usize>>>,
    module_spaces: RefCell<HashMap<String, ResolutionCompletion>>,
    wildcard_inventories: RefCell<HashMap<String, (bool, bool)>>,
    reference_inputs: RefCell<HashMap<CandidatePathIdentity, PythonReferenceInputs>>,
    module_import_inputs: HashMap<EndpointSignature, PythonModuleImportInputs>,
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
    Ok(connection.query_row(
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
        rusqlite::params![summary, container, name],
        |row| row.get(0),
    )?)
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

fn is_module_definition(
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
    reference: SemanticId,
}
#[derive(Default)]
struct PythonReferenceInputs {
    aliases: Vec<PythonImportAlias>,
    deferred_module_scope: Option<u32>,
    resolved_aliases: Vec<PythonAliasTargets>,
}
#[derive(Clone)]
struct PythonAliasTargets {
    container: String,
    name: String,
    targets: Vec<SemanticId>,
    completion: ResolutionCompletion,
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
    rows: std::sync::Arc<PythonBindingRows>,
    blob: i64,
    lookup: ResolutionLookupSemanticRecipe,
    values: Vec<ResolutionSlotValue>,
    prefix: Option<SemanticId>,
    super_context: Option<super_context::SuperContext>,
    references: super::member_access::QualifiedReferenceInputs,
    super_cursor: Option<super_context::SuperCursor>,
    requires_class: bool,
    observations: RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    rendered_order: std::cell::Cell<bool>,
}
impl PythonQualifiedInputs {
    fn view<'a, 'store, 'input>(
        &'a self,
        rules: &'a PythonRules<'a, 'store, 'input>,
        reference: DemandReferenceKey,
    ) -> super::python_members::PythonMemberContext<'a, 'store, 'input> {
        super::python_members::PythonMemberContext {
            rules,
            reference: reference.reference,
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

impl crate::analyzer::resolution::QualifiedMemberProvider for PythonRules<'_, '_, '_> {
    fn poll_construction(
        &mut self,
        input: &crate::analyzer::resolution::TypedConstructionInput,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<Option<ResolutionSlotValue>>> {
        use crate::analyzer::resolution::{
            ClassCreationKind, CloseContinuationId, CloseProgress, CloseResume,
            HierarchyOrderRequest, ResolutionTypeRef, SelectedTypedFactSource, SharedNameInterner,
            TypedFactRequest,
        };
        assert_eq!(input.language, Language::Python);
        crate::profiling::note_with(|| {
            format!(
                "resolution::python_construction reference={:?} targets={:?} complete={}",
                input.reference,
                input.binding.targets(),
                input.binding.completion() == &ResolutionCompletion::Complete,
            )
        });
        let [target] = input.binding.targets() else {
            return Ok(CloseProgress::Ready(None));
        };
        if !super::python_members::is_class(self.ready, *target)? {
            return Ok(CloseProgress::Ready(None));
        }
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Python,
            ResolutionNamespace::Value,
            "__new__",
        )
        .semantic(&self.ready.shared_names());
        match resume {
            CloseResume::Start => Ok(CloseProgress::Members {
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
            }),
            CloseResume::Reference { .. } => {
                unreachable!("construction requests its shared C3 proof")
            }
            CloseResume::Members {
                continuation,
                selection,
            } => {
                continuation.assert_current(provenance);
                let Some(order) = selection.order else {
                    return Ok(CloseProgress::Ready(None));
                };
                crate::profiling::note_with(|| {
                    format!(
                        "resolution::python_construction_order target={target:?} complete={} owners={:?}",
                        provenance.order_status(order).complete,
                        selection.owners,
                    )
                });
                if !provenance.order_status(order).complete {
                    return Ok(CloseProgress::Ready(None));
                }
                let Some(object) = super::python_members::builtin(self.ready, "object") else {
                    return Ok(CloseProgress::Ready(None));
                };
                // Default class creation uses the language's intrinsic type;
                // a source binding with that spelling cannot replace it.
                if super::python_members::builtin(self.ready, "type").is_none() {
                    return Ok(CloseProgress::Ready(None));
                }
                let typed = self.ready.typed_source().with_implicit_environment(
                    self.summary,
                    self.python_version
                        .map(|version| (version.major, version.minor)),
                );
                let mut owners = Vec::new();
                let mut budget_stopped = false;
                if !provenance.visit_order(
                    order,
                    &mut || self.cancellation.is_cancelled(),
                    &mut |entry| {
                        if !self.session.scope_step() {
                            budget_stopped = true;
                            return Ok(());
                        }
                        owners.push(entry.owner);
                        Ok(())
                    },
                )? || budget_stopped
                    || self.cancellation.is_cancelled()
                    || !self.session.observe_cancellation()
                {
                    return Ok(CloseProgress::Cancelled(cancelled_completion()));
                }
                owners.sort_unstable();
                owners.dedup();
                if !owners.contains(&object) || !owners.contains(target) {
                    return Ok(CloseProgress::Ready(None));
                }
                for &owner in &owners {
                    if owner == object {
                        continue;
                    }
                    if !self.session.scope_step() || self.cancellation.is_cancelled() {
                        return Ok(CloseProgress::Cancelled(cancelled_completion()));
                    }
                    let Some(header) = typed.implicit_base_inputs(owner, self.cancellation)? else {
                        return Ok(CloseProgress::Ready(None));
                    };
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_construction_header owner={owner:?} creation={:?} complete={:?} inventory={}",
                            header.creation, header.completion, header.written_inventory_complete,
                        )
                    });
                    if header.creation != ClassCreationKind::Ordinary
                        || !header.written_inventory_complete
                        || header.completion != ResolutionCompletion::Complete
                    {
                        // Expanded bases, replacement decorators and any
                        // unproved metaclass remain explicit open construction.
                        return Ok(CloseProgress::Ready(None));
                    }
                }
                let Some(inventory) =
                    typed.intrinsic_member_inventory(object, self.cancellation)?
                else {
                    return Ok(CloseProgress::Ready(None));
                };
                let digest = self
                    .ready
                    .shared_names()
                    .digest_for_id(lookup.shared_name_id().expect("intrinsic lookup"))
                    .expect("selected intrinsic lookup digest");
                if inventory.presence(digest, ResolutionNamespace::Value)
                    != crate::analyzer::resolution::universe::IntrinsicMemberPresence::Present
                {
                    return Ok(CloseProgress::Ready(None));
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
                        return Ok(CloseProgress::Ready(None));
                    }
                }
                Ok(CloseProgress::Ready(Some(
                    ResolutionSlotValue::type_object(ResolutionTypeRef::new(*target, 0))
                        .constructed_instance(),
                )))
            }
        }
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
            let mut lookup = recipes.into_iter().next().flatten().ok_or_else(|| {
                StoreError::corrupt("typed Python member lacks its selected lookup recipe")
            })?;
            let requires_class = input.namespace == ResolutionNamespace::Type;
            if requires_class {
                lookup = ResolutionLookupSemanticRecipe::new(
                    Language::Python,
                    ResolutionNamespace::Value,
                    lookup.spelling(),
                );
            }
            let super_context = super_context::SuperContext::read(self, input.reference.reference)?;
            let prefix = if input.values.is_empty() {
                match self.root_prefix(mount.blob_id(), input.reference.reference)? {
                    Some(prefix) => {
                        let take = match self.prefix_has_import(&rows, &prefix)? {
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
                        take.then(|| {
                            SemanticId::local(
                                input.reference.reference.ordinal().expect("mounted member"),
                                prefix.prefix,
                            )
                        })
                    }
                    None => None,
                }
            } else {
                None
            };
            let references = super::member_access::QualifiedReferenceInputs::new(
                prefix
                    .into_iter()
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
            let context = PythonQualifiedInputs {
                rows,
                blob: mount.blob_id(),
                lookup,
                values: input.values.clone(),
                prefix,
                super_context,
                requires_class,
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
                    // Classification deliberately ignores binding completion:
                    // prefix_selection applies it to the namespace route, so a
                    // conditional import stays incomplete on that route rather
                    // than falling back to the typed member path.
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
                if slot.context.values.is_empty() {
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
        let input = &slot.access.input;
        let reference = input.reference.reference;
        let context = slot.context.view(self, input.reference);
        let route = super::python_members::PythonMemberRoute {
            lookup: &slot.context.lookup,
            namespace: input.namespace,
            step: input.route_ordinal,
            selection,
            provenance,
        };
        let progress = slot.access.poll(
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
        self.qualified_members.insert(id, slot);
        Ok(progress)
    }
    fn cancel_qualified_member(&mut self, id: crate::analyzer::resolution::QualifiedMemberId) {
        self.qualified_members.remove(&id);
    }
}

pub(super) struct PythonPlacement {
    container: String,
    universe: std::cell::Cell<Option<crate::analyzer::resolution::UniverseEntry>>,
    lexical: RefCell<Option<PythonLexical>>,
    stars: RefCell<HashMap<u32, Vec<(RouteLocation, ResolutionLookupSemanticRecipe)>>>,
}

#[derive(Clone)]
pub(super) struct PythonTarget {
    location: RouteLocation,
    rank: Option<PythonRank>,
    scope: Option<ResolutionScopeId>,
}

pub(super) struct PythonHalf<'a, 'store, 'input> {
    pub(super) rules: &'a PythonRules<'a, 'store, 'input>,
    pub(super) source: &'a SourceHalf,
    placements: Vec<PythonPlacement>,
    import_site: Option<u32>,
    import_name: Option<String>,
    pub(super) rows: std::sync::Arc<PythonBindingRows>,
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
    pub(super) member_observations:
        RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    pub(super) rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
}

struct PythonHalfInputs {
    conditional_imports: Vec<u32>,
    activation_reasons: Vec<SemanticId>,
    endpoint_completion: ResolutionCompletion,
    containers: Vec<String>,
    import_site: Option<u32>,
    import_name: Option<String>,
    rows: std::sync::Arc<PythonBindingRows>,
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
        PythonHalf {
            rules,
            source,
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
            rows: std::sync::Arc::clone(&self.rows),
            fragment: self.fragment,
            blob: self.blob,
            reference_site: self.reference_site,
            deferred_module_scope: self.deferred_module_scope,
            prefix: self.prefix.clone(),
            universe_unmutated: self.universe_unmutated,
            import_aliases: std::rc::Rc::clone(&self.import_aliases),
            module_mutations: std::rc::Rc::clone(&self.module_mutations),
            completion: completion.combine(&self.endpoint_completion),
            stopped: std::cell::Cell::new(false),
            member_observations: RefCell::new(Vec::new()),
            rendered_order: std::rc::Rc::clone(&self.rendered_order),
        }
    }
}

fn open(semantic: SemanticId) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(semantic)])
}

#[derive(Clone)]
struct PythonRootPrefix {
    member: u32,
    prefix: u32,
    site: u32,
    name: String,
}

fn unit_metadata(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
) -> Result<(Vec<u8>, String)> {
    if let Some(metadata) = ready.inventory.python_unit_metadata.borrow().get(&summary) {
        return Ok(metadata.clone());
    }
    let metadata: (Vec<u8>, String) = ready.inventory.connection().query_row(
        "SELECT summary.unit_key,roots.observation FROM resolution_unit_summaries summary JOIN python_unit_summary_roots roots ON roots.summary_id=summary.summary_id WHERE summary.summary_id=?1 LIMIT 1",
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

type PythonModuleBindings = (u32, i64, std::sync::Arc<PythonBindingRows>);

impl PythonRules<'_, '_, '_> {
    pub(super) fn structural_inventory(
        &self,
    ) -> Result<std::cell::Ref<'_, Vec<super::python_members::operations::StructuralMutation>>>
    {
        if self.structural_mutations.borrow().is_none() {
            let mutations = super::python_members::operations::structural_mutations(
                self.ready,
                self.summary,
                self.profile,
                self.session,
                self.cancellation,
            )?;
            *self.structural_mutations.borrow_mut() = Some(mutations);
        }
        Ok(std::cell::Ref::map(
            self.structural_mutations.borrow(),
            |inventory| inventory.as_ref().expect("structural inventory prepared"),
        ))
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

    fn prefix_has_import(
        &self,
        rows: &PythonBindingRows,
        prefix: &PythonRootPrefix,
    ) -> Result<Read<bool>> {
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
        let sites = self.ready.inventory.connection().prepare_cached(
            "SELECT imports.import_site FROM resolution_unit_summary_members member JOIN python_unit_summary_imports imports ON imports.summary_id=member.summary_id AND imports.member_ordinal=member.member_ordinal WHERE member.summary_id=?1 AND member.rel_path=?2 AND member.blob_id=?3 GROUP BY imports.import_site HAVING COUNT(DISTINCT imports.target_container)=1 AND MIN(imports.state='activation_open') AND MIN(EXISTS(SELECT 1 FROM python_unit_summary_providers provider WHERE provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container AND provider.state='selected'))",
        )?.query_map(rusqlite::params![self.summary,caller,blob], |row| row.get::<_,u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let sites = sites
            .into_iter()
            .filter(|site| python_lexical::unconditional_import(rows, *site))
            .collect::<Vec<_>>();
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
        let site: Option<u32> = self.ready.inventory.connection().query_row(
            "SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'",
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
            .query_row(
                "SELECT import_site FROM main.resolution_root_import_demands
             WHERE blob_id=?1 AND target_reference=(
               SELECT reference_source_site FROM main.resolution_root_route_segments
               WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL)
             UNION
             SELECT import_source_site FROM main.resolution_semantic_catalog
             WHERE blob_id=?1 AND local_key=?3 AND import_source_site IS NOT NULL",
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
    ) -> Result<Option<std::sync::Arc<PythonBindingRows>>> {
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.binding_rows.borrow().get(&blob) {
            return Ok(Some(std::sync::Arc::clone(rows)));
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
                .insert(blob, std::sync::Arc::clone(&rows))
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
        for site in import_sites {
            let destinations = self.ready.inventory.connection().prepare_cached(
                "SELECT DISTINCT imported.target_container,imported.requested_name
                 FROM python_unit_summary_imports imported JOIN resolution_unit_summary_members source
                   ON source.summary_id=imported.summary_id AND source.member_ordinal=imported.member_ordinal
                 WHERE imported.summary_id=?1 AND source.blob_id=?2 AND imported.import_site=?3 AND imported.form='from'",
            )?.query_map(rusqlite::params![self.summary,blob,site],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (container, name) in destinations {
                match self.module_import_aliases(&container, &name)? {
                    Read::Ready { value, .. } => aliases.extend(value),
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                }
            }
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

    /// Select the target module's reaching import writers and hand their source
    /// references to the shared scheduler. This also serves bare from-imports.
    fn module_import_aliases(
        &self,
        container: &str,
        name: &str,
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
        let mut state = python_lexical::module_selection(
            &target_rows,
            root.scope,
            name,
            self.profile,
            PythonBindingProofs::default(),
        );
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
                aliases.push(PythonImportAlias {container:container.to_owned(),name:name.to_owned(),reference:SemanticId::local(target_mount,key?)});
            }
        }

        Ok(Read::ready(aliases))
    }
}

impl<'a, 'store, 'input> DemandRules for PythonRules<'a, 'store, 'input> {
    fn prepare_module_imports(
        &mut self,
        frame: &RootFrame,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<()>> {
        use crate::analyzer::resolution::{CloseProgress, CloseResume};
        if !self.module_import_inputs.contains_key(&frame.endpoint) {
            assert!(matches!(resume, CloseResume::Start));
            let mut aliases = Vec::new();
            for half in &frame.halves {
                let SelectedRootPathHalf::Reference {
                    identity,
                    prefix_reference: Some(prefix),
                    ..
                } = half
                else {
                    continue;
                };
                let (_, answer) = inputs
                    .iter()
                    .find(|(key, _)| key.reference == *prefix)
                    .expect("the shared scheduler supplies the selected qualifier");
                let sql_before = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
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
                    let Some(RouteLocation::Container { container, .. }) =
                        self.module_container(&RouteLocation::Owner {
                            definition,
                            scope: None,
                        })?
                    else {
                        continue;
                    };
                    let sql_before = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
                    let discovered = self.module_import_aliases(&container, &name)?;
                    let sql_reads = sql_before
                        .zip(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows())
                        .map(|(before, after)| after.0 - before.0);
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_module_imports container={container:?} name={name:?} sql={sql_reads:?}"
                        )
                    });
                    match discovered {
                        Read::Ready { value, .. } => {
                            aliases.extend(value.into_iter().map(|alias| (*identity, alias)))
                        }
                        Read::Cancelled(completion) | Read::Unavailable { completion, .. } => {
                            return Ok(CloseProgress::Cancelled(completion));
                        }
                    }
                }
                let sql_reads = sql_before
                    .zip(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows())
                    .map(|(before, after)| after.0 - before.0);
                crate::profiling::note_with(|| {
                    format!(
                        "resolution::python_module_import_preparation reference={reference:?} name={name:?} sql={sql_reads:?}"
                    )
                });
            }
            let environment = inputs.first().map(|(key, _)| key.environment);
            let references = super::member_access::QualifiedReferenceInputs::new(
                aliases.iter().map(|(_, alias)| DemandReferenceKey {
                    reference: alias.reference,
                    environment: environment.expect("a qualified member has a prefix environment"),
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
                        targets: answer.targets().to_vec(),
                        completion: answer.completion().clone(),
                    });
            }
            prepared.ready = true;
        }
        self.module_import_inputs
            .insert(frame.endpoint.clone(), prepared);
        Ok(progress)
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
        already_published: bool,
    ) -> Result<Read<EndpointAdmission>> {
        if already_published {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
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
                    .query_row(
                        crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
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
                        self.ready.inventory.connection().query_row(
                            "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports
                             WHERE summary_id=?1 AND import_site=?2 AND form IN ('from','star')
                             AND member_ordinal IN (SELECT member_ordinal FROM resolution_unit_summary_members
                              WHERE summary_id=?1 AND blob_id=?3))",
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
                    self.ready.inventory.connection().query_row(
                        "SELECT EXISTS(SELECT 1 FROM resolution_qualified_routes
                         WHERE blob_id=?1 AND reference=(SELECT source_site FROM resolution_semantic_sites
                          WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'))",
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
                let name: String = self.ready.inventory.connection().query_row(
                    crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
                    rusqlite::params![blob, reference.local_key()],
                    |row| row.get(0),
                )?;
                let containers = self.ready.inventory.connection().prepare_cached(
                    "SELECT provider.container_path FROM python_unit_summary_providers provider
                     JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
                     WHERE provider.summary_id=?1 AND member.blob_id=?2 AND provider.state IN ('selected','alternative')"
                )?.query_map(rusqlite::params![self.summary,blob], |row| row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                let inventory = self.structural_inventory()?;
                let mutations = &*inventory;
                let selected = mutations
                    .iter()
                    .filter(|mutation| {
                        containers
                            .iter()
                            .any(|container| mutation.can_write(container, &name))
                    })
                    .count();
                self.observations.borrow_mut().push(format!("deferred module mutation scan name={name:?} operations={} structural={selected}", mutations.len()));
                if let Some(start) = scan_cpu {
                    let sql = scan_sql
                        .zip(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows())
                        .map(|(before, after)| after.0 - before.0);
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_deferred_module_mutation_scan reference={reference:?} name={name:?} cpu_ns={} sql={sql:?} operations={} structural={selected}",
                            (crate::profiling::thread_cpu_time() - start).as_nanos(),
                            mutations.len()
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
            let SelectedRootPathHalf::Reference { identity, .. } = half else {
                continue;
            };
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
    ) -> Result<Option<Self::Half<'b>>> {
        if let Some(inputs) = self.source_inputs.borrow().get(&source.identity) {
            return Ok(Some(inputs.view(self, source, frame.completion.clone())));
        }
        let Some(mount) = SelectedMountTable::new(&self.ready.inventory)
            .mount_for_fragment(source.identity.fragment())?
        else {
            return Ok(None);
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
        let import_site = self.source_import_site(blob, source.identity, source.token)?;
        let import_name = match import_site {
            Some(site) => self.ready.inventory.connection().query_row(
                "SELECT source_name FROM main.resolution_import_selectors WHERE blob_id=?1 AND site=?2",
                rusqlite::params![blob, site],
                |row| row.get::<_, Option<String>>(0),
            ).optional()?.flatten(),
            None => None,
        };
        let Some(rows) = self.load_binding_rows(blob, Some(mount_record.blob_oid()))? else {
            return Ok(None);
        };
        let reference_site = self.ready.inventory.connection().query_row(
            "SELECT reference_source_site FROM resolution_root_route_segments WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL
             UNION SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?3 AND semantic_role='reference'",
            rusqlite::params![blob, source.identity.path().local_key(), source.token.local_key()], |row| row.get(0),
        ).optional()?;
        let prefix = source.prefix.map(|prefix| {
            let answer = inputs
                .iter()
                .find(|(key, _)| key.reference == prefix)
                .expect("the shared prefix scheduler supplies the selected operand")
                .1;
            std::rc::Rc::new(answer.binding().clone())
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
                        super::python_members::operations::receipt(self, operation, false);
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
                self.ready.inventory.connection().query_row(
                    crate::analyzer::store::python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL,
                    rusqlite::params![blob, site, origin],
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
            conditional_imports,
            activation_reasons,
            endpoint_completion,
            containers: placements
                .into_iter()
                .map(|placement| placement.container)
                .collect(),
            import_site,
            import_name,
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
        Ok(Some(view))
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
        // Binding rows survive publication: selection changes cannot alter a blob's facts.
        for half in &frame.halves {
            match half {
                SelectedRootPathHalf::Reference { identity, .. }
                | SelectedRootPathHalf::Import { identity, .. } => {
                    if let Some(prepared) = self.source_inputs.borrow_mut().remove(identity) {
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
        Ok(Read::ready(ClosurePolicy::new(
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
        )))
    }
}

impl PythonHalf<'_, '_, '_> {
    fn import_route_completion(&self, site: u32) -> Result<ResolutionCompletion> {
        let mount = self.rules.ready.inventory.mount_record_by_ordinal(
            SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
        )?;
        let completion = self.rules.import_route_completion(
            mount.persisted_relative_path(),
            self.blob,
            self.rows
                .imports
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
        placement: &PythonPlacement,
        site: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Vec<(RouteLocation, Option<ResolutionLookupSemanticRecipe>)>> {
        let destinations = self.rules.ready.inventory.connection().prepare_cached(
            "WITH routes AS (
               SELECT imports.*,NOT EXISTS(SELECT 1 FROM resolution_root_import_segments prefix WHERE prefix.blob_id=?4 AND prefix.import_site=imports.import_site) AS binds_head
               FROM python_unit_summary_imports imports
               WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3
             ) SELECT CASE WHEN routes.form='module' AND routes.binds_head THEN binding.container_path WHEN routes.form='module' THEN loaded.container_path ELSE routes.target_container END,routes.form,routes.requested_name
             FROM routes
             LEFT JOIN resolution_import_selectors selector ON selector.blob_id=?4 AND selector.site=routes.import_site
             LEFT JOIN python_unit_summary_providers loaded ON loaded.summary_id=routes.summary_id AND loaded.container_path=routes.target_container
             LEFT JOIN python_unit_summary_providers binding ON routes.form='module' AND routes.binds_head
               AND binding.summary_id=routes.summary_id AND binding.module_name=selector.source_name
               AND binding.root_slot=loaded.root_slot AND binding.state IN ('selected','alternative')",
        )?.query_map(rusqlite::params![self.rules.summary,placement.container,site,self.blob], |row| Ok((row.get::<_,Option<String>>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(destinations
            .into_iter()
            .filter_map(|(container, form, name)| {
                // An external module has no selected provider. Preserve its
                // route obligation, without inventing an empty module container.
                let container = container?;
                let head = (form != "module").then(|| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        lookup.namespace(),
                        if form == "star" {
                            lookup.spelling()
                        } else {
                            &name
                        },
                    )
                });
                Some((
                    RouteLocation::Container {
                        unit: self.rules.summary,
                        container,
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
        let mut proofs = PythonBindingProofs {
            source_completion: Some(self.completion.clone()),
            ..Default::default()
        };
        // Only a deferred lookup that reaches the module cell needs module
        // namespace closure. Local/cell bindings must not wait on these inputs.
        if let Some(module) = self.deferred_module_scope
            && self.module_attribute_space(&placement.container)? != ResolutionCompletion::Complete
        {
            proofs.open_scopes.push(module);
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
        let mount = self.rules.ready.inventory.mount_record_by_ordinal(
            SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
        )?;
        proofs.conditional_imports = self.rules.conditional_imports(
            &self.rows,
            mount.persisted_relative_path(),
            self.blob,
        )?;
        placement.stars.borrow_mut().clear();
        let mut occurrence = self
            .rows
            .events
            .iter()
            .map(|event| event.event)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .expect("event occurrence capacity");
        for import in &self.rows.imports {
            if import.form
                != brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
            {
                continue;
            }
            let site = import.import_site.get();
            let mut starts = Vec::new();
            let mut absent = proofs.conditional_imports.contains(&site);
            let mut inventory_closed = proofs.conditional_imports.contains(&site);
            for (location, head) in self.import_starts(placement, site, lookup)? {
                let RouteLocation::Container { ref container, .. } = location else {
                    unreachable!()
                };
                let present: bool = self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)",
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
                            self.import_route_completion(site)?
                        } else {
                            self.import_route_completion(site)?
                                .combine(&open(self.source.token))
                        },
                    });
                placement.stars.borrow_mut().insert(occurrence, starts);
                occurrence = occurrence.checked_add(1).expect("star occurrence capacity");
            }
        }
        Ok(proofs)
    }
    // Regular packages/modules have one selected provider. Namespace portions
    // are closed only when every retained portion belongs to analysis roots.
    fn provider_completion(&self, container: &str) -> Result<ResolutionCompletion> {
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
        let cached = self.rules.module_spaces.borrow().get(container).cloned();
        let static_completion = if let Some(cached) = cached {
            cached
        } else {
            let mut completion = self.provider_completion(container)?;
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
                    return Ok(completion
                        .combine(&evidence)
                        .combine(&open(self.source.token)));
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
                let dynamic: bool = self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM resolution_gaps gap JOIN resolution_gap_reasons reason ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason WHERE gap.blob_id=?1 AND gap.covers IN (2,5) AND gap.lookup=0 AND reason.origin=?2)", rusqlite::params![blob,origin], |row| row.get(0))?;
                let unresolved_star: bool = self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports imports WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.form='star' AND (imports.state<>'activation_open' OR NOT EXISTS(SELECT 1 FROM python_unit_summary_providers provider WHERE provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container AND provider.state IN ('selected','alternative') AND provider.member_ordinal IS NOT NULL)))",
                    rusqlite::params![self.rules.summary,container], |row|row.get(0))?;
                self.rules.observations.borrow_mut().push(format!(
                    "module attribute-space hook={hook} dynamic={dynamic} unresolved-star={unresolved_star}"
                ));
                if hook || dynamic || unresolved_star {
                    let owner = match self.module_owner(container)? {
                        Some(RouteLocation::Owner { definition, .. }) => definition,
                        _ => self.source.token,
                    };
                    completion = completion.combine(&open(owner));
                }
            }
            self.rules
                .module_spaces
                .borrow_mut()
                .insert(container.to_owned(), completion.clone());
            completion
        };
        let mut completion =
            crate::analyzer::resolution::model::ExactCompletionAccumulator::default();
        let mut cancelled = || self.rules.cancellation.is_cancelled();
        if completion
            .include(&static_completion, &mut cancelled)
            .is_none()
        {
            return Ok(cancelled_completion());
        }
        let owner = self.module_owner(container)?;
        for mutation in self.module_mutations.iter() {
            let incoming = if let Some(RouteLocation::Owner { definition, .. }) = owner {
                mutation.completion(definition)
            } else {
                // A namespace portion has no authored module declaration.
                mutation.namespace_completion(self.source.token)
            };
            if completion.include(&incoming, &mut cancelled).is_none() {
                return Ok(cancelled_completion());
            }
        }
        Ok(completion
            .finish(&mut cancelled)
            .unwrap_or_else(cancelled_completion))
    }

    /// Namespace packages have no authored module declaration.
    fn module_owner(&self, container: &str) -> Result<Option<RouteLocation>> {
        let selected = self.rules.ready.inventory.connection().query_row(
            "SELECT mounted.mount_ordinal, member.blob_id
             FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member
               ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             JOIN selected_resolution_mounts mounted
               ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
             WHERE provider.summary_id=?1 AND provider.container_path=?2
               AND provider.state IN ('selected','alternative') AND provider.kind IN ('module','package')",
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

    fn module_locations(&self, container: &str, name: &str) -> Result<Read<Vec<RouteLocation>>> {
        let mut read = self.module_binding_locations(container, name)?;
        if let Read::Ready { value, completion } = &mut read
            && value.is_empty()
            && *completion == ResolutionCompletion::Complete
            && module_name_open_without_binding(
                self.rules.ready.inventory.connection(),
                self.rules.summary,
                container,
                name,
            )?
        {
            *completion = completion.combine(&open(self.source.token));
        }
        Ok(read)
    }

    fn module_binding_locations(
        &self,
        container: &str,
        name: &str,
    ) -> Result<Read<Vec<RouteLocation>>> {
        let (ordinal, _, rows) = match self.rules.module_bindings(container)? {
            Read::Ready {
                value: Some(value), ..
            } => value,
            Read::Ready { value: None, .. } => {
                return Ok(Read::Ready {
                    value: Vec::new(),
                    completion: self.provider_completion(container)?,
                });
            }
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable { reason, completion });
            }
        };
        let Some(root) = rows.scopes.iter().find(|scope| scope.parent.is_none()) else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(self.source.token),
            });
        };
        let mount_record = self
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let proofs = PythonBindingProofs {
            conditional_imports: self.rules.conditional_imports(
                &rows,
                mount_record.persisted_relative_path(),
                mount_record.blob_id(),
            )?,
            ..Default::default()
        };
        let mut state =
            python_lexical::module_selection(&rows, root.scope, name, self.rules.profile, proofs);
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
        if !rows.slots.iter().any(|slot| slot.scope == root.scope && slot.name == name)
            && !rows.imports.iter().any(|import| import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star)
            && state.selection.stopped.is_none()
        {
            debug_assert!(state.selection.selected.is_empty());
            state.selection.open = false;
            state.selection.residual.clear();
        }
        let mut completion = match self.selection_completion(&state) {
            Read::Ready { completion, .. } => completion,
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { .. } => unreachable!("lexical selection cannot be unavailable"),
        };
        let mount = SelectedMountTable::new(&self.rules.ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let mut value = Vec::new();
        if state.selection.stopped.is_none() {
            for selected in &state.selection.selected {
                let event = rows
                    .events
                    .iter()
                    .find(|event| event.event == selected.occurrence)
                    .expect("selected event belongs to the module inventory");
                if let Some(authored) = self.authored(mount.fragment(), event) {
                    value.push(authored);
                } else if event.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Import {
                    for alias in self.import_aliases.iter().filter(|alias| alias.container == container && alias.name == name) {
                        completion = completion.combine(&alias.completion);
                        value.extend(alias.targets.iter().map(|definition| RouteLocation::Owner { definition: *definition, scope: None }));
                    }
                }
            }
        }
        completion = completion.combine(&self.module_attribute_space(container)?);
        value.sort();
        value.dedup();
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
            completion = completion.combine(&open(self.source.token));
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
        self.completion.clone()
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
        if state.builtin_fallback {
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
        // LOAD_GLOBAL does not invoke module __getattr__; retain source completion
        // (including opaque namespace writes) independently of this residual.
        if !state.selection.open
            && state.selection.unbound.is_empty()
            && state.selection.selected.is_empty()
            && state.selection.stopped.is_none()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_none()
            && !self
                .rows
                .slots
                .iter()
                .any(|slot| slot.scope == scope.get() && slot.name == lookup.spelling())
            && brokk_bifrost_python::intrinsics::builtin(lookup.spelling()).is_none()
            && self.builtin_inventory_closed()
        {
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
            for selected in &state.selection.selected[before..] {
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
                        for (location, head) in
                            self.import_starts(placement, import.import_site.get(), lookup)?
                        {
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
                Some(site) if self.source.is_import => self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND import_site=?2 AND importer_container=?3 AND form='star')",
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
                .query_row(
                    "SELECT slot_site FROM python_unit_summary_export_names
                 WHERE summary_id=?1 AND container_path=?2 AND surface=?3 AND name=?4",
                    rusqlite::params![unit, container, surface, lookup.spelling()],
                    |row| row.get(0),
                )
                .optional()?;
            let policy: Option<String> = self.rules.ready.inventory.connection().query_row(
                "SELECT policy FROM python_unit_summary_surfaces WHERE summary_id=?1 AND container_path=?2 AND surface=?3",
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
                    Some(site) if self.source.is_import => self.rules.ready.inventory.connection().query_row(
                        "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND importer_container=?2 AND import_site=?3 AND form='star')",
                        rusqlite::params![self.rules.summary,placement.container,site],|row|row.get::<_,bool>(0),
                    )?,
                    _ => false,
                };
                if star && !self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)",
                    rusqlite::params![self.rules.summary,container,name], |row|row.get::<_,bool>(0),
                )? {
                    let closed = self.wildcard_inventory_closed(container, name)?;
                    return Ok(Read::Ready { value:Vec::new(), completion: if closed { completion.clone() } else { completion.combine(&open(self.source.token)) } });
                }
                let module_import = match self.import_site {
                    Some(site) if self.source.is_import => self.rules.ready.inventory.connection().query_row(
                        "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND importer_container=?2 AND import_site=?3 AND form='module')",
                        rusqlite::params![self.rules.summary, placement.container, site], |row| row.get::<_, bool>(0),
                    )?,
                    _ => false,
                };
                if module_import
                    || (!self.source.is_import
                        && self.source.route.is_empty()
                        && self.source.prefix.is_none())
                {
                    (
                        self.module_owner(container)?.into_iter().collect(),
                        completion.clone(),
                    )
                } else if star {
                    match self.module_locations(container, name)? {
                        Read::Ready {
                            value,
                            completion: read,
                        } => (value, completion.combine(&read)),
                        Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                        Read::Unavailable { reason, completion } => {
                            return Ok(Read::Unavailable { reason, completion });
                        }
                    }
                } else {
                    // The same terminal tier supplies both authored attributes
                    // and child-module providers. Read it once, then project
                    // source-backed containers through their authored owner.
                    let cursor = WalkCursor {
                        tag: (),
                        location: target.location.clone(),
                        consumed_prefix_segments: self.source.route.len(),
                        start_step: 0,
                        namespace: self.source.demand.namespace(),
                    };
                    let lookup = ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        self.source.demand.namespace(),
                        name,
                    );
                    let tier = (PythonRoute {
                        half: self,
                        placement,
                    })
                    .route_tier(&cursor, &lookup, 0)?
                    .expect("Python's first container tier is present");
                    let mut locations = Vec::new();
                    for location in tier.edges {
                        match location {
                            RouteLocation::Container { container, .. } => {
                                if let Some(owner) = self.module_owner(&container)? {
                                    locations.push(owner);
                                }
                            }
                            RouteLocation::Owner { .. } => locations.push(location),
                        }
                    }
                    (locations, completion.combine(&tier.coverage))
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
            let destinations = self
                .half
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT imports.target_container,imports.form,imports.module_name,coalesce(provider.rel_path,'')
                 FROM main.python_unit_summary_imports imports
                 LEFT JOIN main.python_unit_summary_providers provider
                   ON provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container
                 WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3",
                )?
                .query_map(
                    rusqlite::params![self.half.rules.summary, self.placement.container, site],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            self.half.rules.observations.borrow_mut().push(format!(
                "import-site={site} destinations={:?}",
                destinations
                    .iter()
                    .map(|(_, form, module, path)| (form, module, path))
                    .collect::<Vec<_>>()
            ));
            if destinations.iter().any(|(_, form, _, _)| form != "module") {
                return Ok(RouteStarts {
                    locations: destinations
                        .into_iter()
                        .filter(|(container, _, _, _)| !container.is_empty())
                        .map(|(container, _, _, _)| RouteLocation::Container {
                            unit: self.half.rules.summary,
                            container,
                        })
                        .collect(),
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
        let providers = self
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
        self.half.rules.observations.borrow_mut().push(format!(
            "segment={} providers={:?}",
            segment.spelling(),
            providers
                .iter()
                .map(|(_, module, root, kind, path, state)| (module, root, kind, path, state))
                .collect::<Vec<_>>()
        ));
        // Python reference 7.11: from-import reads the attribute, then imports a missing package child.
        let from_import = self.half.import_site.map_or_else(
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
        let mut edges: Vec<_> = providers
            .into_iter()
            .map(|(container, ..)| RouteLocation::Container {
                unit: *unit,
                container,
            })
            .collect();
        let mut coverage = self.half.provider_completion(container)?;
        if !container.is_empty() {
            let locations = if from_import_child {
                self.half
                    .module_binding_locations(container, segment.spelling())?
            } else {
                self.half.module_locations(container, segment.spelling())?
            };
            match locations {
                Read::Ready { value, completion } => {
                    edges.extend(value);
                    coverage = coverage.combine(&completion);
                }
                Read::Cancelled(completion) | Read::Unavailable { completion, .. } => {
                    coverage = coverage.combine(&completion);
                }
            }
        }
        Ok(Some(RouteEdgeTier {
            edges,
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
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PythonSelectedImportBoundary {
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
            |_, _, _, _, _| {
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
    pub fn python_native_builtin_hierarchy_probe(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        use crate::analyzer::resolution::{SelectedTypedFactSource, SharedNameInterner, universe};
        use std::fmt::Write;
        let typed = self.ready.typed_source().with_implicit_environment(
            summary,
            python_version.map(|version| (version.major, version.minor)),
        );
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
            |mut provider, source, typed, arena, observations| {
                blueprint.with_forward_operation_in_session(
                    source,
                    &paths,
                    typed,
                    cancellation,
                    session,
                    |operation| run(operation, &mut provider, &paths, arena, observations),
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
            |provider, source, typed, _, _| {
                blueprint.with_demand_operation(
                    source,
                    &paths,
                    &paths,
                    typed,
                    provider,
                    cancellation,
                    session,
                    |operation| operation.stage_all_reference_batches(maximum_batch_size, sink),
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
        ) -> Result<T>,
    ) -> Result<T> {
        let (_, observation) = unit_metadata(&self.ready, summary)?;
        let profile = match observation.as_str() {
            "runtime" => PythonBindingProfile::Runtime,
            "typing" => PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python observation profile")),
        };
        let typed = self.ready.typed_source().with_implicit_environment(
            summary,
            python_version.map(|version| (version.major, version.minor)),
        );
        let base = blueprint.path_fragment_source(paths, paths, Some(session));
        let arena = RefCell::new(ClosedRelations::default());
        let observations = RefCell::new(Vec::new());
        let source = ClosedForwardSource::new(&base, paths, &arena, session, CALLER_ENVIRONMENT);
        self.with_shared_forward_provider(
            PythonRules {
                ready: &self.ready,
                summary,
                placement_unit: brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                    b"bifrost-python-placement-unit-v1",
                    &summary.to_le_bytes(),
                ),
                profile,
                python_version,
                cancellation,
                session,
                observations: &observations,
                arena: &arena,
                source_inputs: RefCell::new(HashMap::default()),
                binding_rows: RefCell::new(RequestReadCache::default()),
                placements: RefCell::new(super::placement_access::PlacementMemo::default()),
                root_prefixes: RefCell::new(RequestReadCache::default()),
                module_sites: RefCell::new(RequestReadCache::default()),
                conditional_import_sites: RefCell::new(RequestReadCache::default()),
                super_context_rows: RefCell::new(RequestReadCache::default()),
                member_role_rows: RefCell::new(RequestReadCache::default()),
                qualified_members: HashMap::default(),
                attribute_hooks: RefCell::new(HashMap::default()),
                attribute_mutations: RefCell::new(HashMap::default()),
                attribute_metaclasses: RefCell::new(HashMap::default()),
                prepared_references: RefCell::new(HashMap::default()),
                universe_mutations: RefCell::new(HashMap::default()),
                module_mutations: RefCell::new(HashMap::default()),
                deferred_mutations: RefCell::new(HashMap::default()),
                structural_mutations: RefCell::new(None),
                structural_spaces: RefCell::new(HashMap::default()),
                module_spaces: RefCell::new(HashMap::default()),
                wildcard_inventories: RefCell::new(HashMap::default()),
                reference_inputs: RefCell::new(HashMap::default()),
                module_import_inputs: HashMap::default(),
            },
            &arena,
            paths,
            paths,
            None,
            cancellation,
            session,
            |provider| run(provider, &source, &typed, &arena, &observations),
        )
    }

    fn python_definition_reference(
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
            SelectedResolutionOperationOutcome<
                SelectedResolutionLocated<super::native_units::SelectedNativeReferenceUnits>,
            >,
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
                |operation, provider, _, _, _| {
                    let answer = match operation.resolve_reference_by_demand(reference, provider)? {
                        FactDemandResolution::Ready(answer) => *answer,
                        FactDemandResolution::Cancelled(completion) => return Ok(Err(completion)),
                    };
                    // Binding identity is independent of invocation/application completion.
                    let mut named_reasons =
                        named_reason_details(&self.ready, answer.binding().completion())?;
                    if let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion()
                    {
                        for reason in reasons.iter() {
                            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) =
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
                    let definitions = project_native_definition_units(
                        &self.ready,
                        answer.binding().targets(),
                        &cancellation,
                        session,
                    )?;
                    Ok(Ok(SelectedNativeReferenceUnits {
                        answer,
                        definitions,
                        named_reasons,
                        external_members: Vec::new(),
                        direct_target: None,
                        named_argument: None,
                        predeclared_go_symbol: false,
                        callable_applicability_candidates: Vec::new(),
                        member_contexts: Vec::new(),
                        trace_provenance: Default::default(),
                        declared_visibilities: Vec::new(),
                        absent_member_owners: Vec::new(),
                        diagnostic_identities: Vec::new(),
                    }))
                },
            )?;
            match projected {
                Ok(answer) => {
                    let completion = answer.answer.binding().completion().clone();
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
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        })
    }

    /// Explicit dormant validation assembly. No production query calls this.
    #[doc(hidden)]
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
            |operation, provider, paths, arena, observations| {
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
                        let (begin, finish): (usize,usize) = self.ready.inventory.connection().query_row(
                            "SELECT COALESCE(declaration.name_start_byte,declaration.start_byte),
                                    COALESCE(declaration.name_end_byte,declaration.end_byte)
                             FROM source_native_declaration_bridges bridge
                             JOIN source_declarations declaration ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
                             WHERE bridge.blob_id=?1 AND bridge.source_site=?2",
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
                            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
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
                    for observation in observations.borrow_mut().drain(..) {
                        writeln!(output, "  {observation}").expect("String write");
                    }
                }
                Ok(output)
            },
        )
    }
}
