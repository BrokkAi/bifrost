//! Python exposure rules for the shared reverse nomination worklist. This
//! dormant entry returns nominations, never certain/potential usage answers.
use super::reverse_candidates::{
    REVERSE_LOOKUP_IDENTITY_ARM_SQL, ReverseCandidateKey, ReverseContextWitness,
};
use super::reverse_nomination::{
    ReverseExposure, ReverseExposureSeeds, ReverseExposureStep, ReverseLookupSource,
    ReverseNominationHooks, ReverseSourceLookup, nominate_reverse_target,
};
use super::*;
use rusqlite::{OptionalExtension, params};

/// Python's root reads have no Rust namespace-prefix restriction. Qualified
/// routes still use the shared source-lookup arm; positioned spelling uses the
/// neutral inventory arm. None of these rows is forward binding evidence.
pub(crate) const PYTHON_PREFIXED_ROOT_ARM_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,1,p.path,0
FROM temp.reverse_candidate_keys k
CROSS JOIN main.resolution_paths p INDEXED BY resolution_paths_root_terminal
 ON p.blob_id=k.blob AND p.root_terminal=k.lookup AND p.end_node=-1
CROSS JOIN main.resolution_root_route_segments route
 ON route.blob_id=p.blob_id AND route.path_key=p.path
 AND route.reference_source_site IS NOT NULL
JOIN main.resolution_sites s
 ON s.blob_id=route.blob_id AND s.site=route.reference_source_site AND s.role=0
WHERE k.root
"#;
/// Source observations nominate the actual name expression, independently of
/// ordinary identifier occurrences. Binding confirmation belongs to M4-6b.
pub(crate) const PYTHON_LITERAL_MEMBER_ARM_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,op.name_site,0,9223372036854775806,op.id
FROM temp.reverse_candidate_keys k
JOIN main.resolution_identities lookup ON lookup.id=k.lookup
CROSS JOIN main.python_member_operations op INDEXED BY python_member_operations_inventory
 ON op.blob_id=k.blob AND op.name_kind=0
CROSS JOIN main.python_member_operation_names names INDEXED BY python_member_operation_names_spelling
 ON names.spelling=lookup.spelling AND names.operation=op.id
WHERE k.lexical
"#;
pub(crate) const PYTHON_UNKNOWN_MEMBER_ARM_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,op.name_site,0,9223372036854775806,op.id
FROM temp.reverse_candidate_keys k
JOIN main.resolution_identities lookup ON lookup.id=k.lookup
CROSS JOIN main.python_member_operations op INDEXED BY python_member_operations_inventory
 ON op.blob_id=k.blob AND op.name_kind IN (1,2)
WHERE k.lexical AND (op.name_kind=2 OR EXISTS(
 SELECT 1 FROM main.python_member_operation_names names
 WHERE names.operation=op.id AND substr(lookup.spelling,1,length(names.spelling))=names.spelling))
"#;
pub(crate) const PYTHON_REVERSE_ARMS: &[&str] = &[
    REVERSE_LOOKUP_IDENTITY_ARM_SQL,
    PYTHON_PREFIXED_ROOT_ARM_SQL,
    PYTHON_LITERAL_MEMBER_ARM_SQL,
    PYTHON_UNKNOWN_MEMBER_ARM_SQL,
];
const NAMESPACES: [ResolutionNamespace; 6] = [
    ResolutionNamespace::Value,
    ResolutionNamespace::Type,
    ResolutionNamespace::Callable,
    ResolutionNamespace::Constructor,
    ResolutionNamespace::Constant,
    ResolutionNamespace::Package,
];

/// Selected independently of candidate hits. The summary is the exact retained
/// profile/revision selected by the native publication entry. Provider rows
/// include shadowed alternatives as domain evidence, never positive seeds.
struct PythonReverseView {
    summary: i64,
    unit: Vec<u8>,
    domains: Vec<String>,
}
impl PythonReverseView {
    fn select(operation: &SelectedResolutionOperation<'_, '_>, summary: i64) -> Result<Self> {
        let conn = operation.ready.inventory.connection();
        let (mut unit, digest, output, complete): (Vec<u8>,String,String,bool) = conn.query_row(
            "SELECT unit_key,hex(summary_digest),hex(output_digest),complete FROM resolution_unit_summaries WHERE summary_id=?1 AND lang='python' AND publication_state='complete'", [summary],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let mut domains = vec![format!(
            "environment complete={complete} summary={digest} output={output}"
        )];
        for row in conn.prepare_cached("SELECT root_slot,root_path,authority,ordered,observation,hex(target_digest) FROM python_unit_summary_roots WHERE summary_id=?1 ORDER BY root_slot")?
            .query_map([summary], |row| Ok(format!("root {} {:?} {} ordered={} observation={} target={}", row.get::<_,u32>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,bool>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))? { domains.push(row?); }
        for row in conn.prepare_cached("SELECT provider.container_path,provider.module_name,provider.kind,provider.state,provider.rel_path,source.format, mounts.mount_ordinal FROM python_unit_summary_providers provider LEFT JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal LEFT JOIN python_binding_source source ON source.blob_id=member.blob_id LEFT JOIN temp.selected_resolution_mounts mounts ON mounts.blob_id=member.blob_id AND mounts.persisted_relative_path=member.rel_path AND mounts.storage_language='python' WHERE provider.summary_id=?1 ORDER BY provider.container_path,mounts.mount_ordinal")?
            .query_map([summary], |row| Ok(format!("provider {:?} module={:?} kind={} state={} path={:?} source={} selected={}",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,Option<i64>>(5)?==Some(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT),row.get::<_,Option<u32>>(6)?.is_some())))? {domains.push(row?);}
        for row in conn.prepare_cached("SELECT container_path,surface,policy FROM python_unit_summary_surfaces WHERE summary_id=?1 ORDER BY container_path,surface")?
            .query_map([summary],|row| Ok(format!("surface {:?} {} {}",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))? {domains.push(row?);}
        // M4-2b's environment-wide incompleteness survives every hit and miss.
        domains.push(
            "open=python_environment_open; deferred=forward_confirmation,certain_potential".into(),
        );
        // Reached identities are local to this selected environment attempt,
        // including its revision/profile/overlay authority, even when another
        // profile has the same default Python unit key and container paths.
        unit.extend_from_slice(&summary.to_le_bytes());
        unit.extend_from_slice(&operation.ready.inventory.fingerprint());
        Ok(Self {
            summary,
            unit,
            domains,
        })
    }
}

/// SQL evidence has request lifetime and is cleared even on cancellation/error.
struct ExposureEvidence<'a, 'store, 'input>(&'a SelectedResolutionOperation<'store, 'input>);
impl Drop for ExposureEvidence<'_, '_, '_> {
    fn drop(&mut self) {
        let cleared = self
            .0
            .ready
            .inventory
            .connection()
            .execute("DELETE FROM temp.python_reverse_evidence", [])
            .expect("clear request-local Python reverse evidence");
        self.0
            .ready
            .inventory
            .account_committed_request_changes(cleared as u64);
        let cleared = self
            .0
            .ready
            .inventory
            .connection()
            .execute("DELETE FROM temp.python_reverse_operations", [])
            .expect("clear request-local Python operation evidence");
        self.0
            .ready
            .inventory
            .account_committed_request_changes(cleared as u64);
    }
}
struct PythonReverseHooks<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    view: &'a PythonReverseView,
    cancellation: &'a CancellationToken,
}
impl PythonReverseHooks<'_, '_, '_> {
    fn conn(&self) -> &rusqlite::Connection {
        self.operation.ready.inventory.connection()
    }
    fn exposure(
        &self,
        module: String,
        name: String,
        scope: Option<u32>,
        depth: i64,
    ) -> ReverseExposure {
        ReverseExposure {
            topology: self.view.summary,
            key: self.view.unit.clone(),
            module,
            name,
            scope,
            depth,
        }
    }
    fn record(
        &self,
        kind: &str,
        module: &str,
        blob: i64,
        site: i64,
        name: &str,
        scope: Option<u32>,
    ) -> Result<()> {
        let inserted = self.conn().execute(
            "INSERT OR IGNORE INTO temp.python_reverse_evidence VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                kind,
                module,
                blob,
                site,
                name,
                scope.map(i64::from).unwrap_or(-1)
            ],
        )?;
        self.operation
            .ready
            .inventory
            .account_committed_request_changes(inserted as u64);
        Ok(())
    }
    fn coordinate(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<(SemanticId, i64, i64)>> {
        let path = selected_path_key(target.source().rel_path());
        let Some(mount) = self
            .operation
            .mount_table()
            .mount_for_path("python", &path)?
        else {
            return Ok(None);
        };
        let rows = match self
            .operation
            .ready
            .inventory
            .selected_definition_semantics_for_mount(mount.ordinal(), cancellation)?
        {
            SelectedDefinitionSemanticReadOutcome::Ready(rows) => rows,
            SelectedDefinitionSemanticReadOutcome::Cancelled => return Ok(None),
        };
        let file = ProjectFile::new(
            self.operation.ready.project.root(),
            mount.persisted_relative_path(),
        );
        let prefix = brokk_bifrost_python::declarations::python_module_fq(
            self.operation.ready.project,
            &file,
        );
        let found = match match_selected_definition(&mount, target, &rows, cancellation, |row| {
            let (fq, count) = super::super::hydrate_unit_fq_with_anchor(
                row.fq.as_ref(),
                &row.content_qualifier,
                &file,
                |anchor, _, _| {
                    matches!(anchor, crate::analyzer::PackageAnchor::OwnModule { pop: 0 })
                        .then(|| prefix.clone())
                },
            )?;
            Ok(super::super::code_unit_from_hydrated_row(
                row, &file, fq, count,
            ))
        })? {
            std::ops::ControlFlow::Continue(found) => found,
            std::ops::ControlFlow::Break(()) => return Ok(None),
        };
        let Some(semantic) = found else {
            return Ok(None);
        };
        let lexical = self.operation.ready.lexical_source();
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) =
            lexical.semantic_provenance(semantic, cancellation)?
        else {
            return Ok(None);
        };
        let (blob, site) = self.conn().query_row(
            super::reverse_nomination::REVERSE_DEFINITION_SITE_SQL,
            params![mount.ordinal().get(), local.local_key().get()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(Some((semantic, blob, site)))
    }
    fn keys(&self, blob: i64, name: &str) -> Result<Vec<ReverseCandidateKey>> {
        let mut keys = Vec::new();
        for ordinal in self.conn().prepare_cached("SELECT mount_ordinal FROM temp.selected_resolution_mounts INDEXED BY selected_resolution_mounts_blob_ordinal WHERE blob_id=?1 AND storage_language='python' ORDER BY mount_ordinal")?.query_map([blob],|row|row.get::<_,u32>(0))? {
            let context=ReverseContextWitness::new(self.operation,ordinal?,blob);
            keys.extend(NAMESPACES.into_iter().map(|namespace| ReverseCandidateKey {input_ordinal:0,context:context.clone(),lookup:ResolutionLookupSemanticRecipe::new(Language::Python,namespace,name).semantic(&self.operation.ready.shared_names()),lexical:true,root:true,qualified:true}));
        }
        Ok(keys)
    }
}
impl ReverseNominationHooks for PythonReverseHooks<'_, '_, '_> {
    fn candidate_arms(&self) -> &'static [&'static str] {
        PYTHON_REVERSE_ARMS
    }
    fn locate_reverse_definition(
        &self,
        target: &CodeUnit,
        cancel: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        Ok(self.coordinate(target, cancel)?.map(|row| row.0))
    }
    fn persisted_target(
        &self,
        _: &SelectedResolutionOperationMount,
        target: &CodeUnit,
        cancel: &CancellationToken,
    ) -> Result<Option<(i64, i64)>> {
        // Current selected publication, including replacement content. Never
        // recover the masked base blob just because it has the same path.
        Ok(self
            .coordinate(target, cancel)?
            .map(|(_, blob, site)| (blob, site)))
    }
    fn overlay_routes(
        &self,
        _: &SelectedResolutionOperationMount,
        _: &str,
        _: &CancellationToken,
    ) -> Result<Vec<SelectedSemanticLocator>> {
        Ok(Vec::new())
    }
    fn exposure_seeds(
        &self,
        target: &CodeUnit,
        blob: i64,
        site: i64,
    ) -> Result<ReverseExposureSeeds> {
        let mut exposures = Vec::new();
        let mut sources = HashSet::default();
        sources.insert((blob, target.identifier().to_owned(), None));
        let mut statement=self.conn().prepare_cached("SELECT provider.container_path,slots.name,slots.scope,scopes.parent_scope FROM resolution_binding_events events INDEXED BY resolution_binding_events_authored JOIN resolution_binding_slots slots ON slots.blob_id=events.blob_id AND slots.slot=events.slot JOIN resolution_binding_scopes scopes ON scopes.blob_id=slots.blob_id AND scopes.scope=slots.scope CROSS JOIN resolution_unit_summary_members member INDEXED BY resolution_unit_summary_members_blob ON member.blob_id=events.blob_id AND member.summary_id=?1 CROSS JOIN python_unit_summary_providers provider ON provider.summary_id=member.summary_id AND provider.member_ordinal=member.member_ordinal WHERE events.blob_id=?2 AND events.authored=?3 AND member.rel_path=?4 AND provider.state<>'shadowed'")?;
        for row in statement.query_map(
            params![
                self.view.summary,
                blob,
                site,
                selected_path_key(target.source().rel_path())
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                ))
            },
        )? {
            let (module, name, scope, parent) = row?;
            self.record("seed", &module, blob, site, &name, Some(scope))?;
            exposures.push(self.exposure(module.clone(), name.clone(), Some(scope), 0));
            if parent.is_none() {
                exposures.push(self.exposure(module, name, None, 0));
            }
        }
        Ok(ReverseExposureSeeds {
            exposures,
            sources,
            unbound_spelling: None,
        })
    }
    fn exposure_successors(
        &self,
        exposure: &ReverseExposure,
        _: &[String],
    ) -> Result<ReverseExposureStep> {
        let mut step = ReverseExposureStep {
            candidates: Vec::new(),
            sources: Vec::new(),
            successors: Vec::new(),
        };
        let blob=self.conn().query_row("SELECT member.blob_id FROM python_unit_summary_providers provider JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal WHERE provider.summary_id=?1 AND provider.container_path=?2 AND provider.state<>'shadowed'",params![self.view.summary,exposure.module],|row|row.get::<_,i64>(0)).optional()?;
        if let Some(blob) = blob {
            step.sources
                .push((blob, exposure.name.clone(), exposure.scope));
            if exposure.scope.is_some() {
                // A direct source observation is a possible value edge. Python
                // temporal roots are not Rust lexical scope paths. Join the
                // source inventory directly; temporal confirmation owns exact
                // reaching writes and shadowing, so do not narrow without proof.
                for row in self.conn().prepare_cached(
                    "SELECT events.event,slots.name,slots.scope,scopes.parent_scope
                     FROM resolution_identities lookup INDEXED BY resolution_identities_spelling
                     CROSS JOIN resolution_reference_lookup_identities names
                       INDEXED BY resolution_reference_lookup_identities_identity
                       ON names.identity_id=lookup.id AND names.blob_id=?1
                     JOIN resolution_semantic_sites reference
                       ON reference.blob_id=names.blob_id AND reference.semantic_role='reference'
                      AND reference.semantic_key=names.semantic_key
                     CROSS JOIN resolution_binding_events events INDEXED BY resolution_binding_events_source
                       ON events.blob_id=reference.blob_id AND events.source_reference=reference.source_site
                     JOIN resolution_binding_slots slots ON slots.blob_id=events.blob_id AND slots.slot=events.slot
                     JOIN resolution_binding_scopes scopes ON scopes.blob_id=slots.blob_id AND scopes.scope=slots.scope
                     WHERE lookup.spelling=?2 ORDER BY events.event"
                )?.query_map(params![blob, exposure.name], |row| Ok((
                    row.get::<_, i64>(0)?, row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?, row.get::<_, Option<u32>>(3)?,
                )))? {
                    let (event, name, scope, parent) = row?;
                    if self.cancellation.is_cancelled() {
                        return Ok(step);
                    }
                    self.record("alias", &exposure.module, blob, event, &name, Some(scope))?;
                    step.successors.push(self.exposure(exposure.module.clone(), name.clone(), Some(scope), exposure.depth + 1));
                    if parent.is_none() {
                        step.successors.push(self.exposure(exposure.module.clone(), name, None, exposure.depth + 1));
                    }
                }
            }
        }

        if exposure.scope.is_some() {
            return Ok(step);
        }
        for row in self.conn().prepare_cached("SELECT imports.importer_container,imports.bound_name,imports.form,imports.import_site,member.blob_id,coalesce(binding_slot.scope,root.root_scope),policy.policy,EXISTS(SELECT 1 FROM python_unit_summary_export_names names WHERE names.summary_id=imports.summary_id AND names.container_path=imports.target_container AND names.surface='wildcard' AND names.name=?3) FROM python_unit_summary_imports imports INDEXED BY python_unit_summary_imports_reverse JOIN resolution_unit_summary_members member ON member.summary_id=imports.summary_id AND member.member_ordinal=imports.member_ordinal JOIN python_unit_summary_providers importer ON importer.summary_id=imports.summary_id AND importer.container_path=imports.importer_container AND importer.state<>'shadowed' JOIN resolution_root_imports root ON root.blob_id=member.blob_id AND root.import_site=imports.import_site LEFT JOIN python_binding_imports source_import ON source_import.blob_id=member.blob_id AND source_import.import_site=imports.import_site LEFT JOIN resolution_binding_events binding_event ON binding_event.blob_id=member.blob_id AND binding_event.event=source_import.binding_event LEFT JOIN resolution_binding_slots binding_slot ON binding_slot.blob_id=member.blob_id AND binding_slot.slot=binding_event.slot LEFT JOIN python_unit_summary_surfaces policy ON policy.summary_id=imports.summary_id AND policy.container_path=imports.target_container AND policy.surface='wildcard' WHERE imports.summary_id=?1 AND imports.target_container=?2 AND (imports.requested_name=?3 OR imports.form IN ('module','star')) ORDER BY imports.member_ordinal,imports.import_site,imports.importer_container")?.query_map(params![self.view.summary,exposure.module,exposure.name],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,u32>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,bool>(7)?)))? {
            let(module,bound,form,site,blob,scope,policy,listed)=row?;
            let name=if form=="star" {
                let allowed=match policy.as_deref() {Some("curated")=>listed,Some("public_names")=>!exposure.name.starts_with('_'),Some("absent")=>false,_=>true};
                if !allowed {self.record("star-excluded",&module,blob,site,&exposure.name,Some(scope))?;continue;}
                exposure.name.clone()
            } else {bound};
            self.record(&form,&module,blob,site,&name,Some(scope))?;
            step.successors.push(self.exposure(module.clone(),name.clone(),Some(scope),exposure.depth+1));
            let root:bool=self.conn().query_row("SELECT parent_scope IS NULL FROM resolution_binding_scopes WHERE blob_id=?1 AND scope=?2",params![blob,scope],|row|row.get(0))?;
            if root {step.successors.push(self.exposure(module,name,None,exposure.depth+1));}
        }
        // Namespace portions compose provider children, never source globals.
        for row in self.conn().prepare_cached("SELECT parent.container_path,substr(child.module_name,length(child.parent_module)+2) FROM python_unit_summary_providers child JOIN python_unit_summary_providers parent ON parent.summary_id=child.summary_id AND parent.module_name=child.parent_module AND parent.kind IN ('namespace','package') AND parent.state<>'shadowed' WHERE child.summary_id=?1 AND child.container_path=?2 AND child.state<>'shadowed' ORDER BY parent.container_path")?.query_map(params![self.view.summary,exposure.module],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))? {
            let(parent,name)=row?;
            // Child names are persisted module identities, not reparsed paths.
            // Import routes still preserve their own structured segments.
            self.record("namespace",&parent,-1,-1,&name,None)?;
            step.successors.push(self.exposure(parent,name,None,exposure.depth+1));
        }
        Ok(step)
    }
    fn source_ranges(
        &self,
        _: &CodeUnit,
        _: &HashSet<ReverseLookupSource>,
    ) -> Result<Vec<SelectedSemanticLocator>> {
        Ok(Vec::new())
    }
    fn source_lookup(
        &self,
        blob: i64,
        name: &str,
        _: Option<u32>,
        _: &CancellationToken,
    ) -> Result<ReverseSourceLookup> {
        // Python's temporal roots do not encode scope membership as Rust
        // lookup paths. Keep a conservative source inventory until forward
        // confirmation supplies a binding proof; a cell anchor is not proof.
        Ok(ReverseSourceLookup {
            candidates: Vec::new(),
            keys: self.keys(blob, name)?,
        })
    }
    fn root_lookup(
        &self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<ReverseSourceLookup>> {
        if cancel.is_cancelled() {
            return Ok(None);
        }
        let mut keys = Vec::new();
        for blob in self.conn().prepare_cached("SELECT DISTINCT blob_id FROM temp.selected_resolution_mounts WHERE storage_language='python' ORDER BY blob_id")?.query_map([],|row|row.get::<_,i64>(0))? {keys.extend(self.keys(blob?,name)?);}
        Ok(Some(ReverseSourceLookup {
            candidates: Vec::new(),
            keys,
        }))
    }
    fn observation_sites(
        &self,
        blob: i64,
        site: u32,
        cancel: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionSiteId>>> {
        self.operation
            .ready
            .lexical_source()
            .type_identity_observation_sites(blob, ResolutionSiteId::new(site), cancel)
    }
    fn site_locators(&self, blob: i64, site: u32) -> Result<Vec<SelectedSemanticLocator>> {
        let observed: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM python_member_operations WHERE blob_id=?1 AND name_site=?2) OR (EXISTS(SELECT 1 FROM resolution_binding_observations WHERE blob_id=?1 AND reference=?2)
                AND NOT EXISTS(SELECT 1 FROM resolution_binding_slots WHERE blob_id=?1 AND slot=?2)
                AND NOT EXISTS(
                    SELECT 1 FROM resolution_binding_events events INDEXED BY resolution_binding_events_target
                    JOIN temp.python_reverse_evidence seed ON seed.kind='seed'
                      AND seed.blob=events.blob_id AND seed.site=events.authored
                    WHERE events.blob_id=?1 AND events.target=?2))",
            params![blob, site], |row| row.get(0),
        )?;
        if !observed {
            return Ok(Vec::new());
        }
        super::reverse_nomination::selected_site_locators(
            self.conn(),
            "SELECT persisted_relative_path FROM temp.selected_resolution_mounts INDEXED BY selected_resolution_mounts_blob_ordinal WHERE blob_id=?1 AND storage_language='python' ORDER BY mount_ordinal",
            "python",
            blob,
            site,
        )
    }
}
impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn python_native_reverse_nomination_probe(
        &self,
        summary: i64,
        targets: &[CodeUnit],
        cancel: &CancellationToken,
    ) -> Result<String> {
        let conn = self.ready.inventory.connection();
        let before = conn.total_changes();
        conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS python_reverse_evidence(kind TEXT NOT NULL,container TEXT NOT NULL,blob INTEGER NOT NULL,site INTEGER NOT NULL,name TEXT NOT NULL,scope INTEGER NOT NULL,PRIMARY KEY(kind,container,blob,site,name,scope)) WITHOUT ROWID,STRICT; DELETE FROM temp.python_reverse_evidence")?;
        self.ready
            .inventory
            .account_committed_request_changes(conn.total_changes() - before);
        let before = conn.total_changes();
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS python_reverse_operations(
            mount INTEGER NOT NULL, operation INTEGER NOT NULL, blob INTEGER NOT NULL,
            site INTEGER NOT NULL, name_site INTEGER NOT NULL, form INTEGER NOT NULL,
            effect INTEGER NOT NULL, name_kind INTEGER NOT NULL,
            callee_reference INTEGER, receiver_reference INTEGER, receiver_slot INTEGER,
            possible_replacement INTEGER NOT NULL, patch_target TEXT,
            PRIMARY KEY(mount,operation)) WITHOUT ROWID,STRICT;
            DELETE FROM temp.python_reverse_operations",
        )?;
        conn.execute(
            "INSERT INTO temp.python_reverse_operations(mount,operation,blob,site,name_site,form,effect,name_kind,callee_reference,receiver_reference,receiver_slot,possible_replacement)
            SELECT mounts.mount_ordinal,op.id,op.blob_id,op.site,op.name_site,op.form,
                   op.effect,op.name_kind,op.callee_reference,op.receiver_reference,
                   op.receiver_slot,(op.effect<>0 AND (op.name_kind<>0 OR EXISTS(SELECT 1 FROM python_member_operation_names names WHERE names.operation=op.id)))
            FROM temp.selected_resolution_mounts mounts
            JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?1
            JOIN python_member_operations op ON op.blob_id=mounts.blob_id
            WHERE mounts.storage_language='python'",
            [super::super::python_binding_rows::NATIVE_SOURCE_FORMAT],
        )?;
        self.ready
            .inventory
            .account_committed_request_changes(conn.total_changes() - before);
        let _evidence = ExposureEvidence(self);
        // Only patch-path observations need this bounded per-blob structural
        // read. Reuse its decoded value and retain missing values as unknown.
        let patches = conn.prepare_cached("SELECT mount,operation,blob,name_site FROM temp.python_reverse_operations WHERE form=6")?
            .query_map([], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,u32>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (mount, operation, blob, site) in patches {
            let target =
                super::super::python_member_rows::patch_target_literal(conn, blob, site, cancel)?;
            let changed = conn.execute("UPDATE temp.python_reverse_operations SET patch_target=?3 WHERE mount=?1 AND operation=?2", params![mount,operation,target])?;
            self.ready
                .inventory
                .account_committed_request_changes(changed as u64);
        }
        let view = PythonReverseView::select(self, summary)?;
        let hooks = PythonReverseHooks {
            operation: self,
            view: &view,
            cancellation: cancel,
        };
        let mut output = view.domains.join("\n");
        output.push('\n');
        for row in conn.prepare_cached("SELECT mounts.persisted_relative_path,op.site,op.name_site,
            op.form,op.effect,op.name_kind,op.callee_reference,op.receiver_reference,
            op.receiver_slot,op.possible_replacement,
            coalesce((SELECT group_concat(quote(ordered.spelling),',') FROM
                (SELECT names.spelling FROM python_member_operation_names names
                 WHERE names.operation=op.operation ORDER BY names.ordinal) ordered),''),op.patch_target
            FROM temp.python_reverse_operations op
            JOIN temp.selected_resolution_mounts mounts ON mounts.mount_ordinal=op.mount
            ORDER BY mounts.persisted_relative_path,op.site,op.form")?.query_map([], |row| {
            Ok(format!("operation {:?} site={} name-site={} form={} effect={} name-kind={} callee={:?} receiver={:?} slot={:?} possible-replacement={} names=[{}] patch-target={:?}\n",
                row.get::<_,String>(0)?,row.get::<_,u32>(1)?,row.get::<_,u32>(2)?,
                row.get::<_,u32>(3)?,row.get::<_,u32>(4)?,row.get::<_,u32>(5)?,
                row.get::<_,Option<u32>>(6)?,row.get::<_,Option<u32>>(7)?,
                row.get::<_,Option<u32>>(8)?,row.get::<_,bool>(9)?,row.get::<_,String>(10)?,row.get::<_,Option<String>>(11)?))
        })? { output.push_str(&row?); }
        for target in targets {
            let cleared = conn.execute("DELETE FROM temp.python_reverse_evidence", [])?;
            self.ready
                .inventory
                .account_committed_request_changes(cleared as u64);
            output.push_str(&format!(
                "target {} {}\n",
                selected_path_key(target.source().rel_path()),
                target.identifier()
            ));
            let Some(candidates) = nominate_reverse_target(self, &hooks, target, &[], cancel)?
            else {
                output.push_str("unavailable\n");
                continue;
            };
            output.push_str(&format!("nominations={}\n", candidates.locators.len()));
            for locator in candidates.locators {
                output.push_str(&format!(
                    "candidate {} site={}\n",
                    locator.relative_path(),
                    locator
                        .source_site()
                        .expect("Python nominations have source sites")
                        .get()
                ));
            }
            for row in conn.prepare_cached("SELECT kind,container,name,scope FROM temp.python_reverse_evidence ORDER BY kind,container,name,scope,blob,site")?.query_map([],|row|Ok(format!("exposure {} {:?} {:?} scope={}\n",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?)))? {output.push_str(&row?);}
        }
        Ok(output)
    }
}
