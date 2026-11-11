//! Imported module objects, settled through the shared reference prerequisite pump.
use super::*;
use crate::analyzer::resolution::{CloseProgress, CloseResume, HierarchyProvenanceView};
use crate::analyzer::store::python_member_rows::{
    PythonImportReference, admitted_python_import_member,
};

#[derive(Clone)]
pub(super) struct ImportRoot {
    pub container: String,
    pub member: Option<String>,
    pub observation: Option<PythonModuleObservation>,
}

#[derive(Clone)]
enum ModuleState {
    Unchanged,
    Open(SemanticId),
    Pending {
        owner: SemanticId,
        writes: Vec<RegistryWrite>,
    },
    Redirect {
        owner: SemanticId,
        container: String,
    },
}

#[derive(Clone, Debug)]
enum RegistryWrite {
    Redirect(SemanticId),
    Receiver(SemanticId),
}
impl RegistryWrite {
    fn reference(&self) -> SemanticId {
        match *self {
            Self::Redirect(reference) | Self::Receiver(reference) => reference,
        }
    }
}

#[derive(Default)]
pub(super) struct Registry {
    states: RefCell<HashMap<String, ModuleState>>,
    initialization: RefCell<HashMap<i64, Initialization>>,
    preparations: RefCell<HashMap<EndpointSignature, Preparation>>,
    children: RefCell<HashMap<(String, String), Vec<String>>>,
}

struct Initialization {
    references: HashMap<u32, Option<usize>>,
    latest: HashMap<u32, HashMap<String, usize>>,
}

struct Preparation {
    requests: Vec<(CandidatePathIdentity, ImportRoot)>,
    frontier: Vec<String>,
    seen: HashSet<String>,
    expanded: HashSet<(String, String)>,
    batch: Vec<String>,
    references: Option<super::super::member_access::QualifiedReferenceInputs>,
}

impl PythonRules<'_, '_, '_> {
    pub(super) fn registry_import_roots(&self, ordinal: u32, site: u32) -> Result<Vec<ImportRoot>> {
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let destinations = self.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT imported.target_container,imported.requested_name,imported.form
             FROM python_unit_summary_imports imported
             JOIN resolution_unit_summary_members source
               ON source.summary_id=imported.summary_id AND source.member_ordinal=imported.member_ordinal
             WHERE imported.summary_id=?1 AND source.blob_id=?2 AND source.rel_path=?3 AND imported.import_site=?4",
        )?.query_map(rusqlite::params![self.summary,mount.blob_id(),mount.persisted_relative_path(),site], |row|
            Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut roots = Vec::new();
        for (container, member, form) in destinations {
            if container.is_empty() {
                continue;
            }
            if form == "module" {
                // Workspace imports need the same authored binding prefix as
                // external imports, without the external-provider admission gate.
                let segments = self.ready.inventory.connection().prepare_cached(
                    "SELECT part.value,
                        CASE WHEN NOT EXISTS(SELECT 1 FROM resolution_root_import_segments prefix
                          WHERE prefix.blob_id=authored.blob_id AND prefix.import_site=authored.import_site)
                        THEN 1 ELSE json_array_length(authored.route) END
                     FROM python_binding_imports authored, json_each(authored.route) part
                     WHERE authored.blob_id=?1 AND authored.import_site=?2
                     ORDER BY CAST(part.key AS INTEGER)",
                )?.query_map(rusqlite::params![mount.blob_id(),site], |row|
                    Ok((row.get::<_,String>(0)?,row.get::<_,usize>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let bound = segments
                    .first()
                    .ok_or_else(|| StoreError::corrupt("Python module import has no route"))?
                    .1;
                if bound == segments.len() {
                    roots.push(ImportRoot {
                        container,
                        member: None,
                        observation: None,
                    });
                } else {
                    let name = segments
                        .get(..bound)
                        .ok_or_else(|| {
                            StoreError::corrupt("Python import binding prefix exceeds its route")
                        })?
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(".");
                    let mut statement = self.ready.inventory.connection().prepare_cached(
                        "SELECT parent.container_path FROM python_unit_summary_providers parent
                         JOIN python_unit_summary_providers target
                           ON target.summary_id=parent.summary_id AND target.root_slot=parent.root_slot
                         WHERE parent.summary_id=?1 AND target.container_path=?2 AND parent.module_name=?3
                           AND parent.state IN ('selected','alternative')",
                    )?;
                    for root in statement
                        .query_map(rusqlite::params![self.summary, container, name], |row| {
                            row.get::<_, String>(0)
                        })?
                    {
                        roots.push(ImportRoot {
                            container: root?,
                            member: None,
                            observation: None,
                        });
                    }
                }
            } else if form == "from" {
                roots.push(ImportRoot {
                    container,
                    member: Some(member),
                    observation: Some(PythonModuleObservation {
                        mount: ordinal,
                        import_site: site,
                    }),
                });
            }
        }
        Ok(roots)
    }

    fn registry_state(&self, container: &str) -> Result<ModuleState> {
        if let Some(state) = self.module_registry.states.borrow().get(container).cloned() {
            return Ok(state);
        }
        let state = self.read_registry_state(container)?;
        self.module_registry
            .states
            .borrow_mut()
            .insert(container.to_owned(), state.clone());
        Ok(state)
    }

    fn read_registry_state(&self, container: &str) -> Result<ModuleState> {
        let (ordinal, blob, rows) = match self.module_bindings(container)? {
            Read::Ready {
                value: Some(value), ..
            } => value,
            Read::Ready { value: None, .. } => return Ok(ModuleState::Unchanged),
            Read::Cancelled(_) | Read::Unavailable { .. } => {
                return Err(StoreError::cancelled(
                    "Python module registry read cancelled",
                ));
            }
        };
        let writes = self.ready.inventory.connection().prepare_cached(
            "SELECT writes.registry_reference,writes.key_reference,writes.value_reference,writes.top_level
             FROM python_module_registry_writes writes
             JOIN resolution_sites site ON site.blob_id=writes.blob_id AND site.site=writes.registry_reference
             WHERE writes.blob_id=?1 ORDER BY site.start_byte",
        )?.query_map([blob], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?,row.get::<_,Option<u32>>(2)?,row.get::<_,bool>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if writes.is_empty() {
            return Ok(ModuleState::Unchanged);
        }
        let mount = SelectedMountTable::new(&self.ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let module =
            cached_module_site(self.ready.inventory.connection(), blob, &self.module_sites)?
                .ok_or_else(|| {
                    StoreError::corrupt("a registry write's source has no module declaration")
                })?;
        let owner = crate::analyzer::resolution::mounted_site_semantic(mount.fragment(), module);
        let root = rows
            .scopes
            .iter()
            .find(|scope| scope.parent.is_none())
            .expect("module root");
        let key_written = rows
            .slots
            .iter()
            .filter(|slot| slot.scope == root.scope && slot.name == "__name__")
            .any(|slot| {
                rows.events.iter().any(|event| {
                    event.slot == slot.slot && event.kind != ResolutionBindingEventKind::Annotation
                })
            });
        let path = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let mut candidates = Vec::new();
        for (registry, key, value, top_level) in writes {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(ModuleState::Open(owner));
            }
            if !python_lexical::unconditional_import(&rows, registry) {
                return Ok(ModuleState::Open(owner));
            }
            if !top_level {
                if self.registry_function_unreferenced(blob, registry, &rows)? {
                    continue;
                }
                return Ok(ModuleState::Open(owner));
            }
            if key_written {
                return Ok(ModuleState::Open(owner));
            }
            let spelling: Option<String> = self.ready.inventory.connection().prepare_cached("SELECT name.spelling FROM resolution_semantic_sites reference
                 JOIN resolution_reference_lookup_identities lookup
                   ON lookup.blob_id=reference.blob_id AND lookup.semantic_key=reference.semantic_key
                 JOIN resolution_identities name ON name.id=lookup.identity_id
                 WHERE reference.blob_id=?1 AND reference.source_site=?2 AND reference.semantic_role='reference'")?.query_row(
                rusqlite::params![blob,registry], |row| row.get(0),
            ).optional()?;
            let Some(spelling) = spelling else {
                return Ok(ModuleState::Open(owner));
            };
            let key_is_implicit = rows
                .observations
                .iter()
                .any(|row| row.reference.get() == key && row.execution_scope.get() == root.scope);
            if !key_is_implicit {
                return Ok(ModuleState::Open(owner));
            }
            let admitted = admitted_python_import_member(
                &self.ready.inventory,
                self.summary,
                &rows,
                self.profile,
                PythonImportReference {
                    blob,
                    path: path.persisted_relative_path(),
                    site: registry,
                    spelling: &spelling,
                    member: Some("modules"),
                    ordinary_class_namespace: None,
                },
                self.session,
                self.cancellation,
                self.mutations,
            )?;
            let redirect =
                admitted.is_some_and(|(module, member)| module == "sys" && member == "modules");
            // Non-admission is not negative proof. The native receiver answer
            // must independently establish a complete miss before this write
            // can be ignored. Keep the positive route's RHS proof unchanged.
            let reference = if redirect {
                // A non-reference value is an unknown module object.
                let Some(value) = value else {
                    return Ok(ModuleState::Open(owner));
                };
                value
            } else {
                registry
            };
            let semantic: Option<u32> = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT semantic_key FROM resolution_semantic_sites
                 WHERE blob_id=?1 AND source_site=?2 AND semantic_role='reference'",
                )?
                .query_row(rusqlite::params![blob, reference], |row| row.get(0))
                .optional()?;
            let Some(semantic) = semantic else {
                return Ok(ModuleState::Open(owner));
            };
            let reference = SemanticId::local(ordinal, semantic);
            candidates.push(if redirect {
                RegistryWrite::Redirect(reference)
            } else {
                RegistryWrite::Receiver(reference)
            });
        }
        Ok(if candidates.is_empty() {
            ModuleState::Unchanged
        } else {
            ModuleState::Pending {
                owner,
                writes: candidates,
            }
        })
    }

    /// Earliest module reference that can lead to this function running during
    /// initialization. The full blob result belongs to this operation's rules,
    /// never to a retained selection.
    pub(super) fn function_initialization_start(
        &self,
        blob: i64,
        reference: u32,
        rows: &PythonBindingRows,
    ) -> Result<Option<usize>> {
        if !self
            .module_registry
            .initialization
            .borrow()
            .contains_key(&blob)
        {
            let result = self.build_initialization(blob, rows)?;
            self.module_registry
                .initialization
                .borrow_mut()
                .insert(blob, result);
        }
        Ok(self.module_registry.initialization.borrow()[&blob]
            .references
            .get(&reference)
            .copied()
            .unwrap_or(Some(0)))
    }

    pub(super) fn initialization_has_later(
        &self,
        blob: i64,
        scope: u32,
        name: &str,
        point: usize,
    ) -> bool {
        self.module_registry.initialization.borrow()[&blob]
            .latest
            .get(&scope)
            .and_then(|names| names.get(name))
            .is_some_and(|latest| *latest > point)
    }

    fn build_initialization(&self, blob: i64, rows: &PythonBindingRows) -> Result<Initialization> {
        let connection = self.ready.inventory.connection();
        let references = connection.prepare_cached(
            "SELECT observed.reference, CASE WHEN sites.owner>=0 THEN sites.owner END, name.spelling, EXISTS(SELECT 1 FROM resolution_call_obligations call WHERE call.blob_id=semantic.blob_id AND call.callee_reference=semantic.semantic_key)
             FROM resolution_binding_observations observed
             LEFT JOIN resolution_sites sites ON sites.blob_id=observed.blob_id AND sites.site=observed.reference AND sites.role=0
             LEFT JOIN resolution_semantic_sites semantic ON semantic.blob_id=observed.blob_id AND semantic.source_site=observed.reference AND semantic.semantic_role='reference'
             LEFT JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id AND lookup.semantic_key=semantic.semantic_key
             LEFT JOIN resolution_identities name ON name.id=lookup.identity_id
             WHERE observed.blob_id=?1 AND semantic.semantic_key IS NOT NULL",
        )?.query_map([blob], |row| Ok((row.get::<_,u32>(0)?, row.get::<_,Option<u32>>(1)?, row.get::<_,Option<String>>(2)?, row.get::<_,bool>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let write_targets: HashSet<_> = rows
            .events
            .iter()
            .filter(|event| event.kind != ResolutionBindingEventKind::Augment)
            .map(|event| event.target)
            .collect();
        // Binding observations also serve navigation of write tokens. A def
        // or assignment target does not read the previously bound value.
        let references = references
            .into_iter()
            .filter(|(site, _, _, _)| !write_targets.contains(site))
            .collect::<Vec<_>>();
        let functions = rows
            .events
            .iter()
            .filter(|event| event.kind == ResolutionBindingEventKind::Function)
            .collect::<Vec<_>>();
        let scope_owners = connection.prepare_cached(
            "SELECT node.source_scope, definition.source_site
             FROM resolution_member_scope_properties properties
             JOIN resolution_node_catalog node ON node.blob_id=properties.blob_id AND node.local_key=properties.scope_head_node_key
             JOIN resolution_semantic_sites definition ON definition.blob_id=properties.blob_id AND definition.semantic_key=properties.definition_semantic_key AND definition.semantic_role='definition'
             WHERE properties.blob_id=?1 AND properties.scope_kind='executable'
             ORDER BY 1,2",
        )?.query_map([blob], |row| Ok((row.get::<_,u32>(0)?, row.get::<_,u32>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let observations: HashMap<_, _> = rows
            .observations
            .iter()
            .map(|row| (row.reference.get(), row))
            .collect();
        let scopes: HashMap<_, _> = rows.scopes.iter().map(|row| (row.scope, row)).collect();
        // Neither key is unique in the schema, so the first row wins. A scope
        // with two owner rows takes the lowest definition site (ORDER BY 1,2).
        // Events arrive in PythonBindingRows order (commit_byte, phase, event,
        // all descending), so a declaration maps to its latest Function event.
        let mut owners = HashMap::default();
        for (scope, owner) in scope_owners {
            owners.entry(scope).or_insert(owner);
        }
        let mut authored = HashMap::default();
        for (index, function) in functions.iter().enumerate() {
            if let Some(site) = function.authored {
                authored.entry(site).or_insert(index);
            }
        }
        // Resolve each scope once, iteratively, including unnamed executable scopes.
        let mut enclosing = HashMap::default();
        for scope in scopes.keys() {
            let mut current = *scope;
            let mut path = Vec::new();
            let owner = loop {
                if let Some(owner) = enclosing.get(&current) {
                    break *owner;
                }
                path.push(current);
                if let Some(owner) = owners.get(&current) {
                    break authored.get(owner).copied();
                }
                match scopes[&current].parent {
                    Some(parent) => current = parent,
                    None => break None,
                }
            };
            for scope in path {
                enclosing.insert(scope, owner);
            }
        }
        let slots: HashMap<_, _> = rows.slots.iter().map(|slot| (slot.slot, slot)).collect();
        let slot_names: HashSet<_> = rows.slots.iter().map(|slot| slot.name.as_str()).collect();
        let known_names: HashSet<_> = rows
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    ResolutionBindingEventKind::Function | ResolutionBindingEventKind::Class
                )
            })
            .map(|event| slots[&event.slot].name.as_str())
            .collect();
        let referenced_names: HashSet<_> = references
            .iter()
            .filter_map(|(_, _, name, _)| name.as_deref())
            .collect();
        let mut by_name: HashMap<&str, Vec<usize>> = HashMap::default();
        for (index, function) in functions.iter().enumerate() {
            by_name
                .entry(slots[&function.slot].name.as_str())
                .or_default()
                .push(index);
        }
        let referenced_functions: Vec<_> = functions
            .iter()
            .enumerate()
            .filter(|(_, function)| referenced_names.contains(slots[&function.slot].name.as_str()))
            .map(|(index, _)| index)
            .collect();
        let root = rows
            .scopes
            .iter()
            .find(|scope| scope.parent.is_none())
            .expect("module root")
            .scope;
        let decorators = connection.prepare_cached(
            "SELECT declaration, expression_site FROM python_member_decorators WHERE blob_id=?1",
        )?.query_map([blob], |row| Ok((row.get::<_,u32>(0)?, row.get::<_,u32>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut decorator_points = HashMap::default();
        for (declaration, expression) in decorators {
            let point = observations.get(&expression).map(|row| row.point_byte);
            let entry = decorator_points.entry(declaration).or_insert(None::<usize>);
            if let Some(point) = point {
                *entry = Some(entry.map_or(point, |previous| previous.min(point)));
            }
        }
        // Applying a decorator passes the newly created function as a value,
        // including call-shaped expressions, before its module name is bound.
        let mut edges = vec![Vec::new(); functions.len() + 1];
        for (index, function) in functions.iter().enumerate() {
            if let Some(point) = function
                .authored
                .and_then(|site| decorator_points.get(&site))
            {
                let caller = enclosing[&function.execution_scope];
                edges[caller.unwrap_or(functions.len())].push((index, point.unwrap_or(0)));
            }
        }
        for (site, _owner, name, call) in &references {
            let Some(observed) = observations.get(site) else {
                continue;
            };
            // Header/default/decorator references execute in the enclosing
            // execution scope, even when declaration ownership names the def.
            let mut scope = observed.execution_scope.get();
            while scope != root && scopes[&scope].class_body {
                scope = scopes[&scope].parent.expect("class parent");
            }
            // Comprehensions can run during initialization; an enclosing named
            // function still controls when their references participate.
            let caller = enclosing[&scope];
            let known = name.as_deref().is_some_and(|name| {
                known_names.contains(name)
                    || brokk_bifrost_python::intrinsics::builtin(name).is_some()
            });
            // An unknown call can invoke any escaped/referenced function.
            // A missing lookup identity likewise cannot exclude a target.
            let mut binding_open = false;
            if let Some(name) = name {
                if let Some(mut selection) = python_lexical::lexical_selection(
                    rows,
                    *site,
                    name,
                    PythonBindingProfile::Runtime,
                    PythonBindingProofs::default(),
                ) {
                    let mut budget = SessionBudget {
                        session: self.session,
                        cancellation: self.cancellation,
                    };
                    python_lexical::select_lexical(
                        &mut selection,
                        rows,
                        &mut budget,
                        self.cancellation,
                    )?;
                    binding_open =
                        selection.selection.open || selection.selection.selected.is_empty();
                } else {
                    binding_open = true;
                }
            }
            let unshadowed_builtin = name.as_ref().is_some_and(|name| {
                brokk_bifrost_python::intrinsics::builtin(name).is_some()
                    && !slot_names.contains(name.as_str())
            });
            let undecided =
                name.is_none() || (binding_open && !unshadowed_builtin) || (*call && !known);

            let targets = if undecided {
                referenced_functions.as_slice()
            } else {
                name.as_deref()
                    .and_then(|name| by_name.get(name))
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
            };
            for &index in targets {
                if functions[index].target != *site {
                    edges[caller.unwrap_or(functions.len())].push((index, observed.point_byte));
                }
            }
        }
        // All module edges are seeds. Process points in ascending order so each
        // function is settled once, with its earliest reachable module point.
        let mut starts = vec![None; functions.len()];
        let mut seeds = std::mem::take(&mut edges[functions.len()]);
        seeds.sort_unstable_by_key(|&(_, point)| point);
        let mut work = Vec::new();
        for (target, point) in seeds {
            work.push(target);
            while let Some(index) = work.pop() {
                if starts[index].is_some() {
                    continue;
                }
                starts[index] = Some(point);
                for &(target, _) in &edges[index] {
                    if starts[target].is_none() {
                        work.push(target);
                    }
                }
            }
        }
        let references = rows
            .observations
            .iter()
            .map(|row| {
                (
                    row.reference.get(),
                    enclosing[&row.execution_scope.get()].map_or(Some(0), |index| starts[index]),
                )
            })
            .collect();
        let mut latest: HashMap<u32, HashMap<String, usize>> = HashMap::default();
        // Preserve every event considered by the original later-write predicate.
        for event in &rows.events {
            let slot = slots[&event.slot];
            let point = latest
                .entry(slot.scope)
                .or_default()
                .entry(slot.name.clone())
                .or_insert(0);
            *point = (*point).max(event.commit_byte);
        }
        Ok(Initialization { references, latest })
    }

    fn registry_function_unreferenced(
        &self,
        blob: i64,
        registry: u32,
        rows: &PythonBindingRows,
    ) -> Result<bool> {
        Ok(self
            .function_initialization_start(blob, registry, rows)?
            .is_none())
    }

    pub(super) fn module_has_registry(&self, container: &str) -> Result<bool> {
        Ok(!matches!(
            self.registry_state(container)?,
            ModuleState::Unchanged
        ))
    }

    /// Only module-object projections call this walk. Source lexical selection
    /// and the module's own dictionary always keep their authored source rows.
    pub(super) fn imported_module_view(
        &self,
        container: &str,
    ) -> Result<(String, ResolutionCompletion)> {
        let mut current = container.to_owned();
        let mut visited = HashSet::default();
        loop {
            let state = self.registry_state(&current)?;
            match state {
                ModuleState::Unchanged => return Ok((current, ResolutionCompletion::Complete)),
                ModuleState::Open(owner) | ModuleState::Pending { owner, .. } => {
                    return Ok((current, open(owner)));
                }
                ModuleState::Redirect { owner, container } => {
                    if !visited.insert(current) {
                        return Ok((container, open(owner)));
                    }
                    current = container;
                }
            }
        }
    }

    pub(super) fn begin_module_registries(
        &self,
        endpoint: &EndpointSignature,
        requests: Vec<(CandidatePathIdentity, ImportRoot)>,
    ) {
        let frontier = requests
            .iter()
            .map(|(_, root)| root.container.clone())
            .collect();
        assert!(
            self.module_registry
                .preparations
                .borrow_mut()
                .insert(
                    endpoint.clone(),
                    Preparation {
                        requests,
                        frontier,
                        seen: HashSet::default(),
                        expanded: HashSet::default(),
                        batch: Vec::new(),
                        references: None,
                    }
                )
                .is_none()
        );
    }

    pub(super) fn module_registries_started(&self, endpoint: &EndpointSignature) -> bool {
        self.module_registry
            .preparations
            .borrow()
            .contains_key(endpoint)
    }

    fn registry_children(&self, container: &str, name: &str) -> Result<Vec<String>> {
        let key = (container.to_owned(), name.to_owned());
        if let Some(children) = self.module_registry.children.borrow().get(&key).cloned() {
            return Ok(children);
        }
        let children = self.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT child.container_path FROM python_unit_summary_providers parent
             JOIN python_unit_summary_providers child ON child.summary_id=parent.summary_id
               AND child.root_slot=parent.root_slot AND child.module_name=parent.module_name || '.' || ?3
             JOIN resolution_unit_summary_members member
               ON member.summary_id=child.summary_id AND member.member_ordinal=child.member_ordinal
             WHERE parent.summary_id=?1 AND parent.container_path=?2 AND parent.kind IN ('package','namespace')
               AND child.state IN ('selected','alternative')
               AND EXISTS(SELECT 1 FROM python_module_registry_writes writes WHERE writes.blob_id=member.blob_id)",
        )?.query_map(rusqlite::params![self.summary,container,name], |row| row.get::<_,String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        self.module_registry
            .children
            .borrow_mut()
            .insert(key, children.clone());
        Ok(children)
    }

    pub(super) fn poll_module_registries(
        &self,
        endpoint: &EndpointSignature,
        provenance: HierarchyProvenanceView<'_>,
        mut resume: CloseResume<'_>,
    ) -> Result<CloseProgress<Vec<(CandidatePathIdentity, ImportRoot)>>> {
        let mut prepared = self
            .module_registry
            .preparations
            .borrow_mut()
            .remove(endpoint)
            .expect("registry preparation started");
        if prepared.requests.is_empty() {
            return Ok(CloseProgress::Ready(Vec::new()));
        }
        loop {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(CloseProgress::Cancelled(cancelled_completion()));
            }
            if let Some(references) = &mut prepared.references {
                let progress =
                    references.poll(provenance, resume, self.session, self.cancellation)?;
                match progress {
                    CloseProgress::Ready(()) => {}
                    CloseProgress::Reference {
                        continuation,
                        key,
                        completion,
                    } => {
                        self.module_registry
                            .preparations
                            .borrow_mut()
                            .insert(endpoint.clone(), prepared);
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
                        unreachable!("registry values request reference answers")
                    }
                }
                for container in prepared.batch.drain(..) {
                    // A nested reference prerequisite may have settled this
                    // same module through another preparation while we waited.
                    // Reuse that result rather than overwrite its proof.
                    let (owner, writes) = match self.registry_state(&container)? {
                        ModuleState::Pending { owner, writes } => (owner, writes),
                        ModuleState::Redirect { container, .. } => {
                            prepared.frontier.push(container);
                            continue;
                        }
                        ModuleState::Unchanged | ModuleState::Open(_) => continue,
                    };
                    let mut target = None;
                    let mut complete = true;
                    for write in writes {
                        let reference = write.reference();
                        let answer = references
                            .answers()
                            .find(|(key, _)| key.reference == reference)
                            .expect("registry prerequisite settled")
                            .1;
                        if let RegistryWrite::Receiver(_) = write {
                            // Same native complete-miss condition as navigation:
                            // an empty complete binding has no predeclared target.
                            // External alternatives and absent provenance do not
                            // authorize a negative module-effect answer.
                            if answer.binding().completion() == &ResolutionCompletion::Complete
                                && answer.binding().targets().is_empty()
                                && selected_external_imports(self.external_imports, reference)
                                    .is_empty()
                                && answer.site_metadata().is_some_and(|metadata| {
                                    matches!(
                                        metadata.site_kind(),
                                        ResolutionSiteKind::ValueReference
                                            | ResolutionSiteKind::CallableReference
                                            | ResolutionSiteKind::TypeReference
                                    )
                                })
                            {
                                continue;
                            }
                            if answer.binding().completion() == &ResolutionCompletion::Complete {
                                let mut declared_types = answer.projections().iter().filter(|projection| {
                                    matches!(projection.kind(), brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetDeclaredValueType | brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetTypeOrDeclaredValueType)
                                }).peekable();
                                let mut non_module = declared_types.peek().is_some();
                                for projection in declared_types {
                                    let Some(frontier) =
                                        answer.projected_frontiers().iter().find(|frontier| {
                                            frontier.slot() == projection.output_slot()
                                        })
                                    else {
                                        non_module = false;
                                        break;
                                    };
                                    if frontier.completion() != &ResolutionCompletion::Complete
                                        || !frontier.unindexed_external().is_empty()
                                        || frontier.possible_values().is_empty()
                                    {
                                        non_module = false;
                                        break;
                                    }
                                    for value in frontier.possible_values() {
                                        if !matches!(value, ResolutionSlotValue::Runtime { .. })
                                            || value.obligation().is_some()
                                            || super::super::python_members::builtin_class(
                                                self,
                                                value.ty().identity(),
                                            )?
                                            .is_none()
                                        {
                                            non_module = false;
                                            break;
                                        }
                                    }
                                }
                                if non_module {
                                    continue;
                                }
                            }
                            complete = false;
                            break;
                        }
                        let answer = answer.binding();
                        if answer.completion() != &ResolutionCompletion::Complete {
                            complete = false;
                            break;
                        }
                        let [definition] = answer.targets() else {
                            complete = false;
                            break;
                        };
                        let Some(RouteLocation::Container { container, .. }) = self
                            .module_container(&RouteLocation::Owner {
                                definition: *definition,
                                scope: None,
                            })?
                        else {
                            complete = false;
                            break;
                        };
                        target = Some(container);
                    }
                    let state = if complete {
                        if let Some(target) = target {
                            prepared.frontier.push(target.clone());
                            ModuleState::Redirect {
                                owner,
                                container: target,
                            }
                        } else {
                            ModuleState::Unchanged
                        }
                    } else {
                        ModuleState::Open(owner)
                    };
                    self.module_registry
                        .states
                        .borrow_mut()
                        .insert(container, state);
                }
                prepared.references = None;
                resume = CloseResume::Start;
            }
            while let Some(container) = prepared.frontier.pop() {
                if !prepared.seen.insert(container.clone()) {
                    continue;
                }
                match self.registry_state(&container)? {
                    ModuleState::Pending { .. } => prepared.batch.push(container),
                    ModuleState::Redirect { container, .. } => prepared.frontier.push(container),
                    ModuleState::Unchanged | ModuleState::Open(_) => {}
                }
            }
            if !prepared.batch.is_empty() {
                let mut keys = Vec::new();
                for container in &prepared.batch {
                    let ModuleState::Pending { writes, .. } = self.registry_state(container)?
                    else {
                        unreachable!("pending registry batch");
                    };
                    keys.extend(writes.iter().map(|write| DemandReferenceKey {
                        reference: write.reference(),
                        environment: CALLER_ENVIRONMENT,
                    }));
                }
                prepared.references = Some(
                    super::super::member_access::QualifiedReferenceInputs::new(keys),
                );
                continue;
            }
            for (_, request) in &prepared.requests {
                let Some(member) = &request.member else {
                    continue;
                };
                let (container, completion) = self.imported_module_view(&request.container)?;
                if completion != ResolutionCompletion::Complete
                    || !prepared
                        .expanded
                        .insert((container.clone(), member.clone()))
                {
                    continue;
                }
                // An earlier attribute in this package's initialization wins.
                if let Some(site) =
                    self.initializing_package_import(&container, request.observation)?
                    && let Read::Ready {
                        value: Some((_, _, rows)),
                        ..
                    } = self.module_bindings(&container)?
                {
                    let mut state = python_lexical::initializing_module_selection(
                        &rows,
                        site,
                        member,
                        self.profile,
                        PythonBindingProofs::default(),
                    )
                    .expect("initializing import");
                    let scope = state.start_scope;
                    python_lexical::lexical_tier(
                        &mut state,
                        &rows,
                        scope,
                        &mut SessionBudget {
                            session: self.session,
                            cancellation: self.cancellation,
                        },
                    );
                    if !state.selection.selected.is_empty()
                        && !state.selection.open
                        && state.selection.residual.is_empty()
                        && state.selection.unbound.is_empty()
                    {
                        continue;
                    }
                }
                prepared
                    .frontier
                    .extend(self.registry_children(&container, member)?);
            }
            if prepared.frontier.is_empty() {
                return Ok(CloseProgress::Ready(prepared.requests));
            }
        }
    }
}

// Reflective mutations in a deferred invocation belong on the query ledger,
// independently of whether initialization can bind the original module exactly.
pub(in crate::analyzer::store::resolution_operation) fn deferred_registry_obligation(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
    cancellation: &CancellationToken,
) -> Result<Option<crate::analyzer::resolution::QueryObligation>> {
    if cancellation.is_cancelled() {
        return Err(StoreError::cancelled(
            "Python deferred registry inventory cancelled",
        ));
    }
    let count: u64 = ready.inventory.connection().prepare_cached("WITH RECURSIVE execution(blob_id,reference,scope) AS (
           SELECT writes.blob_id,writes.registry_reference,observed.execution_scope
           FROM python_module_registry_writes writes
           JOIN resolution_unit_summary_members member ON member.blob_id=writes.blob_id
           JOIN resolution_binding_observations observed ON observed.blob_id=writes.blob_id AND observed.reference=writes.registry_reference
           WHERE member.summary_id=?1 AND writes.top_level=0
           UNION
           SELECT execution.blob_id,execution.reference,scopes.parent_scope FROM execution
           JOIN resolution_binding_scopes scopes ON scopes.blob_id=execution.blob_id AND scopes.scope=execution.scope
           WHERE scopes.parent_scope IS NOT NULL)
         SELECT COUNT(*) FROM (SELECT DISTINCT execution.blob_id,execution.reference FROM execution
           JOIN resolution_binding_scopes scopes ON scopes.blob_id=execution.blob_id AND scopes.scope=execution.scope
           WHERE scopes.parent_scope IS NOT NULL AND NOT EXISTS(
             SELECT 1 FROM resolution_member_scope_properties properties
             JOIN resolution_node_catalog node ON node.blob_id=properties.blob_id AND node.local_key=properties.scope_head_node_key
             WHERE properties.blob_id=scopes.blob_id AND properties.scope_kind='type_body' AND node.source_scope=scopes.scope))")?.query_row(
        [summary], |row| row.get(0),
    )?;
    Ok((count != 0).then(|| {
        crate::analyzer::resolution::QueryObligation::new(
            "python_dynamic_receiver_mutation_open",
            format!("registry_writes={count}"),
            "",
        )
    }))
}
