//! Python exposure rules for the production reverse nomination worklist.
mod construction;
use super::super::python_unit_summaries::PythonSelectedEnvironment;
use super::reverse_candidates::{
    REVERSE_LOOKUP_IDENTITY_ARM_SQL, ReverseCandidateKey, ReverseContextWitness,
};
use super::reverse_nomination::{
    ReverseExposure, ReverseExposureSeeds, ReverseExposureStep, ReverseLookupSource,
    ReverseNominationHooks, ReverseSourceLookup, nominate_reverse_target,
};
use super::*;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableReceiverOrigin;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use rusqlite::{OptionalExtension, params};
use std::cell::Cell;
use std::path::Path;

/// Scan budget, independent of the usages assembler's final result cap.
#[derive(Clone, Copy, Debug)]
pub struct PythonReverseLimits {
    pub max_sites: usize,
}
impl Default for PythonReverseLimits {
    fn default() -> Self {
        Self { max_sites: 100_000 }
    }
}

struct PythonReverseRequest<'a> {
    scope: Option<&'a UsageScanScope<'a>>,
    limits: PythonReverseLimits,
    session: Option<&'a ResolutionSession>,
    cancellation: &'a CancellationToken,
}

impl PythonReverseRequest<'_> {
    fn stop_reason(&self, retained: usize) -> Option<&'static str> {
        if self.cancellation.is_cancelled() {
            Some("cancelled")
        } else if self.cancellation.soft_deadline_passed() {
            Some("time_stopped")
        } else if retained >= self.limits.max_sites {
            Some("python_reverse_scan_limit")
        } else if self.session.is_some_and(|session| {
            !matches!(session.finish(()), BoundedResolution::Complete { .. })
        }) {
            Some("python_reverse_session_stopped")
        } else {
            None
        }
    }
}

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
/// Known prefixes nominate matching targets as undecided candidates. Wholly
/// unknown names enter through the target's namespace exposures below, never
/// through this spelling arm. Constant names lost by the producer are #7182.
pub(crate) const PYTHON_UNKNOWN_MEMBER_ARM_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,op.name_site,0,9223372036854775806,op.id
FROM temp.reverse_candidate_keys k
JOIN main.resolution_identities lookup ON lookup.id=k.lookup
CROSS JOIN main.python_member_operations op INDEXED BY python_member_operations_inventory
 ON op.blob_id=k.blob AND op.name_kind=1
WHERE k.lexical AND EXISTS(
 SELECT 1 FROM main.python_member_operation_names names
 WHERE names.operation=op.id AND substr(lookup.spelling,1,length(names.spelling))=names.spelling)
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
    inventory: Vec<String>,
    context: PythonReverseContext,
    obligations: Vec<PythonReverseObligation>,
    query_obligations: Vec<String>,
    unplaced: Vec<String>,
    mutation_guard: super::python_members::operations::PythonMutationReadGuard,
}
impl PythonReverseView {
    fn select(
        operation: &SelectedResolutionOperation<'_, '_>,
        summary: i64,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let conn = operation.ready.inventory.connection();
        let (mut unit, digest, output, complete): (Vec<u8>,String,String,bool) = conn.prepare_cached("SELECT unit_key,hex(summary_digest),hex(output_digest),complete FROM resolution_unit_summaries WHERE summary_id=?1 AND lang='python' AND publication_state='complete'")?.query_row( [summary],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let mut domains = vec![format!(
            "environment complete={complete} summary={digest} output={output}"
        )];
        for row in conn.prepare_cached("SELECT root_slot,root_path,authority,ordered,observation,hex(target_digest) FROM python_unit_summary_roots WHERE summary_id=?1 ORDER BY root_slot")?
            .query_map([summary], |row| Ok(format!("root {} {:?} {} ordered={} observation={} target={}", row.get::<_,i64>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,bool>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))? { domains.push(row?); }
        for row in conn.prepare_cached("SELECT provider.container_path,provider.module_name,provider.kind,provider.state,provider.rel_path,source.format, mounts.mount_ordinal FROM python_unit_summary_providers provider LEFT JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal LEFT JOIN python_binding_source source ON source.blob_id=member.blob_id LEFT JOIN temp.selected_resolution_mounts mounts ON mounts.blob_id=member.blob_id AND mounts.persisted_relative_path=member.rel_path AND mounts.storage_language='python' WHERE provider.summary_id=?1 ORDER BY provider.container_path,mounts.mount_ordinal")?
            .query_map([summary], |row| Ok(format!("provider {:?} module={:?} kind={} state={} path={:?} source={} selected={}",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,Option<i64>>(5)?==Some(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT),row.get::<_,Option<u32>>(6)?.is_some())))? {domains.push(row?);}
        for row in conn.prepare_cached("SELECT container_path,surface,policy FROM python_unit_summary_surfaces WHERE summary_id=?1 ORDER BY container_path,surface")?
            .query_map([summary],|row| Ok(format!("surface {:?} {} {}",row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))? {domains.push(row?);}
        // M4-2b's environment-wide incompleteness survives every hit and miss.
        domains.push("open=python_environment_open".into());
        // Reached identities are local to this selected environment attempt,
        // including its revision/profile/overlay authority, even when another
        // profile has the same default Python unit key and container paths.
        unit.extend_from_slice(&summary.to_le_bytes());
        unit.extend_from_slice(&operation.ready.inventory.fingerprint());
        let profile = conn
            .prepare_cached(
                "SELECT observation FROM python_unit_summary_roots WHERE summary_id=?1 LIMIT 1",
            )?
            .query_row([summary], |row| row.get::<_, String>(0))?;
        let raw_unit = conn
            .prepare_cached("SELECT unit_key FROM resolution_unit_summaries WHERE summary_id=?1")?
            .query_row([summary], |row| row.get::<_, Vec<u8>>(0))?;
        let gaps = conn.prepare_cached("SELECT gap_kind,subject,json(detail) FROM resolution_unit_summary_gaps WHERE summary_id=?1 ORDER BY gap_kind,subject")?
            .query_map([summary], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut obligations = Vec::new();
        let mut unplaced = Vec::new();
        let mutation_profile = match profile.as_str() {
            "runtime" => super::python_lexical::PythonBindingProfile::Runtime,
            "typing" => super::python_lexical::PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python reverse profile")),
        };
        let session = ResolutionSession::unbounded();
        let mutations = super::python_members::operations::PythonMutationQuery::new(
            &operation.ready,
            summary,
            mutation_profile,
            &session,
            cancellation,
        )?;
        let mutation_guard = mutations.derived_read_guard()?;
        let mut query_obligations =
            super::python_demand::selected_environment_obligations(&operation.ready, summary)?;
        if let Some(obligation) = mutations.dynamic_receiver_obligation()? {
            query_obligations.insert(obligation);
        }
        if let Some(obligation) =
            super::python_demand::module_registry::deferred_registry_obligation(
                &operation.ready,
                summary,
                cancellation,
            )?
        {
            query_obligations.insert(obligation);
        }
        let query_obligations = query_obligations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        for (kind, subject, detail) in gaps {
            let label = format!("{kind}:{subject}:{detail}");
            // The selected environment is the certainty boundary. Runtime path
            // mutation and unacquired external providers are query obligations,
            // not missing proof for each selected-environment binding.
            if kind == "python_unknown_placement" {
                // Importability describes the selected environment, not a
                // missing reference. The file's own source references still
                // participate in nomination and confirmation below.
                unplaced.push(subject);
                continue;
            }
            if kind == "python_environment_open" {
                continue;
            }
            let mut hash = CanonicalHasher::new(b"python-reverse-environment-obligation:v1");
            hash.field("unit", &raw_unit);
            hash.field("profile", profile.as_bytes());
            hash.field("gap", label.as_bytes());
            let reason = operation.ready.context_identities.named_semantic(
                hash.finish(),
                "python_reverse_environment_gap",
                &label,
            );
            obligations.push(PythonReverseObligation {
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
                label,
                caller: (kind == "python_unknown_placement").then_some(subject),
                coverage: PythonReverseCoverage::Enumeration,
            });
        }
        // Activation and unacquired providers are already stated by the
        // query-wide environment obligation. Only a missing relative context
        // is a caller-local loss inside the selected workspace.
        for row in conn.prepare_cached("SELECT DISTINCT members.rel_path,imports.import_site,imports.state FROM python_unit_summary_imports imports JOIN resolution_unit_summary_members members ON members.summary_id=imports.summary_id AND members.member_ordinal=imports.member_ordinal WHERE imports.summary_id=?1 AND imports.state='relative_context_open' ORDER BY members.rel_path,imports.import_site")?
            .query_map([summary], |row| Ok((row.get::<_,String>(0)?,row.get::<_,u32>(1)?,row.get::<_,String>(2)?)))? {
            let (caller, site, state) = row?;
            let (completion, label) = super::python_demand::import_route_obligation(&operation.ready, summary, &caller, site, &state)?;
            obligations.push(PythonReverseObligation { completion, label, caller:Some(caller), coverage:PythonReverseCoverage::CandidatesAndEnumeration });
        }
        let view = Self {
            summary,
            unit,
            inventory: domains,
            context: PythonReverseContext {
                summary,
                profile: match profile.as_str() {
                    "runtime" => super::python_lexical::PythonBindingProfile::Runtime,
                    "typing" => super::python_lexical::PythonBindingProfile::Typing,
                    _ => return Err(StoreError::corrupt("invalid Python reverse profile")),
                },
                unit: raw_unit,
            },
            obligations,
            query_obligations,
            unplaced,
            mutation_guard,
        };
        view.validate_current_use(operation, cancellation)?;
        Ok(view)
    }

    fn validate_current_use(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.mutation_guard
            .validate_current_use(&operation.ready, cancellation)
    }
}

enum PythonReverseCoverage {
    Enumeration,
    CandidatesAndEnumeration,
}

struct PythonReverseObligation {
    coverage: PythonReverseCoverage,
    completion: ResolutionCompletion,
    label: String,
    caller: Option<String>,
}
impl PythonReverseObligation {
    fn affects(&self, path: &str) -> bool {
        self.caller.as_deref().is_none_or(|caller| caller == path)
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
            .prepare_cached("DELETE FROM temp.python_reverse_evidence")
            .expect("prepare request-local Python reverse evidence cleanup")
            .execute([])
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
            .prepare_cached("DELETE FROM temp.python_reverse_operations")
            .expect("prepare request-local Python operation evidence cleanup")
            .execute([])
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
    coordinate: Option<(SemanticId, i64, i64)>,
    target: &'a CodeUnit,
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
    // The shared reached set keys exposures by this language-owned key. A
    // module object binding and a mirrored surface can have the same spelling,
    // but admit different successor imports. Both retain selected-view identity.
    fn module_object_exposure(
        &self,
        module: String,
        name: String,
        scope: Option<u32>,
        depth: i64,
    ) -> ReverseExposure {
        let mut exposure = self.exposure(module, name, scope, depth);
        exposure.key.extend_from_slice(b"python-module-object");
        exposure
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
        let inserted = self
            .conn()
            .prepare_cached(
                "INSERT OR IGNORE INTO temp.python_reverse_evidence VALUES(?1,?2,?3,?4,?5,?6)",
            )?
            .execute(params![
                kind,
                module,
                blob,
                site,
                name,
                scope.map(i64::from).unwrap_or(-1)
            ])?;
        self.operation
            .ready
            .inventory
            .account_committed_request_changes(inserted as u64);
        Ok(())
    }
    fn coordinates(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(SemanticId, i64, i64)>> {
        let path = selected_path_key(target.source().rel_path());
        let Some(mount) = self
            .operation
            .mount_table()
            .mount_for_path("python", &path)?
        else {
            return Ok(Vec::new());
        };
        if target.is_module() {
            let file = ProjectFile::new(
                self.operation.ready.project.root(),
                mount.persisted_relative_path(),
            );
            // Reuse the path-synthetic module constructor used by the adapter.
            if brokk_bifrost_python::declarations::module_code_unit(
                self.operation.ready.project,
                &file,
            )
            .as_ref()
                != Some(target)
            {
                return Ok(Vec::new());
            }
            let blob = self
                .operation
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?
                .blob_id();
            return Ok(
                super::python_demand::module_declaration_site(self.conn(), blob)?
                    .map(|site| {
                        (
                            crate::analyzer::resolution::mounted_site_semantic(
                                mount.fragment(),
                                site,
                            ),
                            blob,
                            i64::from(site.get()),
                        )
                    })
                    .into_iter()
                    .collect(),
            );
        }
        let mut rows = match self
            .operation
            .ready
            .inventory
            .selected_definition_semantics_for_mount(mount.ordinal(), cancellation)?
        {
            SelectedDefinitionSemanticReadOutcome::Ready(rows) => rows.into_vec(),
            SelectedDefinitionSemanticReadOutcome::Cancelled => return Ok(Vec::new()),
        };
        // The crosswalk is injective on CodeUnit. Unclaimed authored
        // definitions still project through their source-declaration bridges.
        let unclaimed = self.conn().prepare_cached("SELECT semantic.semantic_key FROM resolution_semantic_sites semantic WHERE semantic.blob_id=?1 AND semantic.semantic_role='definition' AND NOT EXISTS(SELECT 1 FROM resolution_definition_unit_crosswalks crosswalk WHERE crosswalk.blob_id=semantic.blob_id AND crosswalk.definition_semantic_key=semantic.semantic_key) ORDER BY semantic.semantic_key")?
            .query_map([self.operation.ready.inventory.mount_record_by_ordinal(mount.ordinal())?.blob_id()],|row|Ok((mount.ordinal(),ResolutionLocalKey::new(row.get(0)?))))?.collect::<rusqlite::Result<Vec<_>>>()?;
        match self
            .operation
            .ready
            .inventory
            .selected_declaration_units(&unclaimed, cancellation)?
        {
            SelectedDefinitionUnitReadOutcome::Ready(units) => {
                rows.extend(units.into_vec().into_iter().map(|(_, key, row)| (key, row)))
            }
            SelectedDefinitionUnitReadOutcome::Cancelled => return Ok(Vec::new()),
        }
        let file = ProjectFile::new(
            self.operation.ready.project.root(),
            mount.persisted_relative_path(),
        );
        let prefix = self
            .operation
            .ready
            .definition_module_anchor(mount.ordinal(), &file)?
            .ok_or_else(|| {
                StoreError::corrupt("selected Python file lacks its published module anchor")
            })?;
        let found = match match_selected_definitions(&mount, target, &rows, cancellation, |row| {
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
            std::ops::ControlFlow::Break(()) => return Ok(Vec::new()),
        };
        let lexical = self.operation.ready.lexical_source();
        let mut coordinates = Vec::new();
        for semantic in found {
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) =
                lexical.semantic_provenance(semantic, cancellation)?
            else {
                return Ok(Vec::new());
            };
            let (blob, site) = self
                .conn()
                .prepare_cached(super::reverse_nomination::REVERSE_DEFINITION_SITE_SQL)?
                .query_row(
                    params![mount.ordinal().get(), local.local_key().get()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
            coordinates.push((semantic, blob, site));
        }
        coordinates.sort_unstable();
        coordinates.dedup();
        Ok(coordinates)
    }
    fn coordinate(&self) -> (SemanticId, i64, i64) {
        self.coordinate
            .expect("nomination hooks select one authored definition from the full unit group")
    }
    fn keys(&self, blob: i64, name: &str) -> Result<Vec<ReverseCandidateKey>> {
        let mut keys = Vec::new();
        for ordinal in self.conn().prepare_cached("SELECT mount_ordinal FROM temp.selected_resolution_mounts INDEXED BY selected_resolution_mounts_blob_ordinal WHERE blob_id=?1 AND storage_language='python' ORDER BY mount_ordinal")?.query_map([blob],|row|row.get::<_,u32>(0))? {
            let context=ReverseContextWitness::new(self.operation,ordinal?,blob);
            keys.extend(NAMESPACES.into_iter().map(|namespace| ReverseCandidateKey {input_ordinal:0,context:context.clone(),lookup:ResolutionLookupSemanticRecipe::new(Language::Python,namespace,name).semantic(&self.operation.ready.shared_names()),lexical:true,root:true,qualified:true}));
        }
        Ok(keys)
    }

    /// Reuse namespace reverse exposures to reach receiver references. In particular,
    /// a star export carries a module surface, while a named member export does
    /// not associate the exporting module object with the imported module.
    fn receiver_candidates(
        &self,
    ) -> Result<HashMap<SelectedSemanticLocator, PythonReverseReceiver>> {
        let namespaces = self.conn().prepare_cached(
            "SELECT DISTINCT member.rel_path FROM temp.python_reverse_evidence evidence
             JOIN python_unit_summary_providers provider
               ON provider.summary_id=?1 AND provider.container_path=evidence.container
              AND provider.state<>'shadowed'
             JOIN resolution_unit_summary_members member
               ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             WHERE evidence.kind='receiver-namespace'",
        )?.query_map([self.view.summary], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut units = Vec::new();
        for path in namespaces {
            if self.cancellation.is_cancelled() {
                break;
            }
            let file = ProjectFile::new(self.operation.ready.project.root(), path);
            let Some(module) = brokk_bifrost_python::declarations::module_code_unit(
                self.operation.ready.project,
                &file,
            ) else {
                continue;
            };
            units.push(module);
        }
        let classes = self
            .conn()
            .prepare_cached(
                "SELECT DISTINCT mounts.mount_ordinal,scope.definition_semantic_key
             FROM temp.python_reverse_evidence evidence
             JOIN resolution_member_scope_properties scope
               ON scope.blob_id=evidence.blob AND scope.scope_kind='type_body'
             JOIN resolution_node_catalog node
               ON node.blob_id=scope.blob_id AND node.local_key=scope.scope_head_node_key
              AND node.source_scope=evidence.scope
             JOIN temp.selected_resolution_mounts mounts ON mounts.blob_id=evidence.blob
              AND mounts.storage_language='python'
             WHERE evidence.kind='receiver-scope'",
            )?
            .query_map([], |row| Ok(SemanticId::local(row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some(classes) = super::native_units::project_native_definition_units_each(
            &self.operation.ready,
            &classes,
            self.cancellation,
        )? {
            units.extend(
                classes
                    .into_iter()
                    .filter_map(|(_, definition)| match definition {
                        Some(SelectedNativeDefinition::Unit(unit)) => Some(unit),
                        _ => None,
                    }),
            );
        }
        let mut receivers: HashMap<SelectedSemanticLocator, PythonReverseReceiver> =
            HashMap::default();
        for unit in units {
            if self.cancellation.is_cancelled() {
                break;
            }
            for coordinate in self.coordinates(&unit, self.cancellation)? {
                let hooks = PythonReverseHooks {
                    operation: self.operation,
                    view: self.view,
                    cancellation: self.cancellation,
                    coordinate: Some(coordinate),
                    target: &unit,
                };
                let Some(candidates) =
                    nominate_reverse_target(self.operation, &hooks, &unit, &[], self.cancellation)?
                else {
                    continue;
                };
                for receiver in candidates.locators {
                    let mount = self
                        .operation
                        .mount_table()
                        .mount_for_path("python", receiver.relative_path())?
                        .expect("selected receiver caller");
                    let blob = self
                        .operation
                        .ready
                        .inventory
                        .mount_record_by_ordinal(mount.ordinal())?
                        .blob_id();
                    let reference = receiver.source_site().expect("receiver source reference");
                    let sites = self.conn().prepare_cached(
                        "SELECT op.name_site,semantic.semantic_key
                         FROM python_member_operations op INDEXED BY python_member_operations_inventory
                         JOIN resolution_semantic_sites semantic
                           ON semantic.blob_id=op.blob_id AND semantic.source_site=op.receiver_reference
                          AND semantic.semantic_role='reference'
                         WHERE op.blob_id=?1 AND op.name_kind=2 AND op.receiver_reference=?2",
                    )?.query_map(params![blob, reference.get()], |row| {
                        Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?))
                    })?.collect::<rusqlite::Result<Vec<_>>>()?;
                    for (site, semantic) in sites {
                        let locator = SelectedSemanticLocator::new(
                            "python",
                            receiver.relative_path().to_owned(),
                            ResolutionSiteId::new(site),
                            LoweredSemanticRole::Reference,
                        );
                        receivers
                            .entry(locator)
                            .or_insert_with(|| PythonReverseReceiver {
                                reference: SemanticId::local(mount.ordinal().get(), semantic),
                                owners: Vec::new(),
                            })
                            .owners
                            .push(coordinate.0);
                    }
                }
            }
        }
        for receiver in receivers.values_mut() {
            receiver.owners.sort_unstable();
            receiver.owners.dedup();
        }
        Ok(receivers)
    }
}

struct PythonReverseReceiver {
    reference: SemanticId,
    owners: Vec<SemanticId>,
}
impl ReverseNominationHooks for PythonReverseHooks<'_, '_, '_> {
    fn candidate_arms(&self) -> &'static [&'static str] {
        PYTHON_REVERSE_ARMS
    }
    fn locate_reverse_definition(
        &self,
        _target: &CodeUnit,
        _cancel: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        Ok(Some(self.coordinate().0))
    }
    fn persisted_target(
        &self,
        _: &SelectedResolutionOperationMount,
        _target: &CodeUnit,
        _cancel: &CancellationToken,
    ) -> Result<Option<(i64, i64)>> {
        // Current selected publication, including replacement content. Never
        // recover the masked base blob just because it has the same path.
        let (_, blob, site) = self.coordinate();
        Ok(Some((blob, site)))
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
        if target.is_module() {
            let providers = self.conn().prepare_cached(
                "SELECT provider.container_path FROM python_unit_summary_providers provider
                 JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
                 WHERE provider.summary_id=?1 AND member.blob_id=?2 AND member.rel_path=?3
                   AND provider.kind IN ('module','package') AND provider.state<>'shadowed'",
            )?.query_map(params![self.view.summary, blob, selected_path_key(target.source().rel_path())], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for container in providers {
                self.record(
                    "module-seed",
                    &container,
                    blob,
                    site,
                    target.identifier(),
                    None,
                )?;
                exposures.push(self.exposure(container, target.identifier().to_owned(), None, 0));
            }
        }
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
        let module_surface = self.target.is_module() && exposure.key == self.view.unit;
        let target_surface = module_surface
            && self
                .conn()
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM temp.python_reverse_evidence
             WHERE kind='module-seed' AND container=?1 AND blob=?2 AND site=?3)",
                )?
                .query_row(
                    params![exposure.module, self.coordinate().1, self.coordinate().2],
                    |row| row.get::<_, bool>(0),
                )?;
        let mut step = ReverseExposureStep {
            candidates: Vec::new(),
            sources: Vec::new(),
            successors: Vec::new(),
        };
        let blob=self.conn().prepare_cached("SELECT member.blob_id FROM python_unit_summary_providers provider JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal WHERE provider.summary_id=?1 AND provider.container_path=?2 AND provider.state<>'shadowed'")?.query_row(params![self.view.summary,exposure.module],|row|row.get::<_,i64>(0)).optional()?;
        if let Some(blob) = blob {
            if let Some(scope) = exposure.scope {
                self.record(
                    "receiver-scope",
                    &exposure.module,
                    blob,
                    -1,
                    "",
                    Some(scope),
                )?;
            } else if !(self.target.is_module() && exposure.depth == 0) {
                self.record("receiver-namespace", &exposure.module, blob, -1, "", None)?;
            }
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
                    let mut alias = self.exposure(exposure.module.clone(), name.clone(), Some(scope), exposure.depth + 1);
                    alias.key = exposure.key.clone();
                    step.successors.push(alias);
                    if parent.is_none() {
                        let mut alias = self.exposure(exposure.module.clone(), name, None, exposure.depth + 1);
                        alias.key = exposure.key.clone();
                        step.successors.push(alias);
                    }
                }
            }
        }

        if exposure.scope.is_some() {
            return Ok(step);
        }
        // Only from-imports rename a member; module imports bind its container.
        for row in self.conn().prepare_cached("SELECT imports.importer_container,imports.bound_name,imports.form,imports.import_site,member.blob_id,coalesce(binding_slot.scope,root.root_scope),policy.policy,EXISTS(SELECT 1 FROM python_unit_summary_export_names names WHERE names.summary_id=imports.summary_id AND names.container_path=imports.target_container AND names.surface='wildcard' AND names.name=?3) FROM python_unit_summary_imports imports INDEXED BY python_unit_summary_imports_reverse JOIN resolution_unit_summary_members member ON member.summary_id=imports.summary_id AND member.member_ordinal=imports.member_ordinal JOIN python_unit_summary_providers importer ON importer.summary_id=imports.summary_id AND importer.container_path=imports.importer_container AND importer.state<>'shadowed' JOIN resolution_root_imports root ON root.blob_id=member.blob_id AND root.import_site=imports.import_site LEFT JOIN python_binding_imports source_import ON source_import.blob_id=member.blob_id AND source_import.import_site=imports.import_site LEFT JOIN resolution_binding_events binding_event ON binding_event.blob_id=member.blob_id AND binding_event.event=source_import.binding_event LEFT JOIN resolution_binding_slots binding_slot ON binding_slot.blob_id=member.blob_id AND binding_slot.slot=binding_event.slot LEFT JOIN python_unit_summary_surfaces policy ON policy.summary_id=imports.summary_id AND policy.container_path=imports.target_container AND policy.surface='wildcard' WHERE imports.summary_id=?1 AND imports.target_container=?2 AND ((imports.form='from' AND imports.requested_name=?3) OR imports.form='star' OR (?4 AND imports.form='module')) ORDER BY imports.member_ordinal,imports.import_site,imports.importer_container")?.query_map(params![self.view.summary,exposure.module,exposure.name,target_surface],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,u32>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,bool>(7)?)))? {
            let(module,bound,form,site,blob,scope,policy,listed)=row?;
            // A named export from a surface names a member, not its module.
            if module_surface && form == "from" { continue; }
            if form == "module" {
                // The retained root route ends at the actually bound object.
                // Unaliased `import pkg.child` binds pkg; an alias binds child.
                let whole: bool = self.conn().prepare_cached("SELECT (SELECT count(*) FROM resolution_root_import_segments prefix
                             WHERE prefix.blob_id=source.blob_id AND prefix.import_site=source.import_site)+1=source.module_segments
                     FROM python_binding_imports source WHERE source.blob_id=?1 AND source.import_site=?2")?.query_row(
                    params![blob,site], |row| row.get(0),
                )?;
                if !whole { continue; }
            }
            let name=if form=="star" {
                // A module target denotes the imported surface, rather than
                // an exported member bearing the module's own spelling.
                let allowed=module_surface || match policy.as_deref() {Some("curated")=>listed,Some("public_names")=>!exposure.name.starts_with('_'),Some("absent")=>false,_=>true};
                if !allowed {self.record("star-excluded",&module,blob,site,&exposure.name,Some(scope))?;continue;}
                exposure.name.clone()
            } else {bound};
            self.record(&form,&module,blob,site,&name,Some(scope))?;
            let successor = |scope| {
                if self.target.is_module() && (!module_surface || form == "module") {
                    self.module_object_exposure(module.clone(), name.clone(), scope, exposure.depth+1)
                } else {
                    self.exposure(module.clone(), name.clone(), scope, exposure.depth+1)
                }
            };
            // A star-mirrored surface has no local cell bearing the module name.
            if !(module_surface && form == "star") { step.successors.push(successor(Some(scope))); }
            let root:bool=self.conn().prepare_cached("SELECT parent_scope IS NULL FROM resolution_binding_scopes WHERE blob_id=?1 AND scope=?2")?.query_row(params![blob,scope],|row|row.get(0))?;
            if root {step.successors.push(successor(None));}
        }
        // A module qualifier is not an alias of a contained declaration.
        // Qualified member uses are nominated by their terminal spelling.
        if !target_surface {
            return Ok(step);
        }
        // Namespace portions compose provider children, never source globals.
        for row in self.conn().prepare_cached("SELECT parent.container_path,substr(child.module_name,length(child.parent_module)+2) FROM python_unit_summary_providers child JOIN python_unit_summary_providers parent ON parent.summary_id=child.summary_id AND parent.module_name=child.parent_module AND parent.root_slot=child.root_slot AND parent.kind IN ('namespace','package') AND parent.state<>'shadowed' WHERE child.summary_id=?1 AND child.container_path=?2 AND child.state<>'shadowed'
            UNION
            SELECT parent.container_path,substr(child.module_name,length(child.parent_module)+2)
            FROM python_unit_summary_providers child
            JOIN python_unit_summary_spellings spelling ON spelling.summary_id=child.summary_id AND spelling.target_container=child.container_path AND spelling.admitted
            JOIN python_unit_summary_providers parent ON parent.summary_id=child.summary_id AND parent.kind IN ('namespace','package') AND parent.state IN ('selected','alternative')
            WHERE child.summary_id=?1 AND child.container_path=?2 AND child.state IN ('selected','alternative')
              AND (spelling.module_name=parent.module_name || '.' || substr(child.module_name,length(child.parent_module)+2)
                OR EXISTS(SELECT 1 FROM python_unit_summary_spellings prefix WHERE prefix.summary_id=spelling.summary_id AND prefix.source_root=spelling.source_root AND prefix.target_container=parent.container_path AND prefix.admitted AND spelling.module_name=prefix.module_name || '.' || substr(child.module_name,length(child.parent_module)+2)))
              AND EXISTS(SELECT 1 FROM python_unit_summary_imports imported WHERE imported.summary_id=child.summary_id AND imported.target_container=child.container_path AND imported.module_name=spelling.module_name)
            ORDER BY 1")?.query_map(params![self.view.summary,exposure.module],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))? {
            let(parent,name)=row?;
            // Child names are persisted module identities, not reparsed paths.
            // Import routes still preserve their own structured segments.
            self.record("namespace",&parent,-1,-1,&name,None)?;
            step.successors.push(self.module_object_exposure(parent,name,None,exposure.depth+1));
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
        // The synthetic callee-value read retains qualifier, service and context
        // reasons the call reference may lack. It is an operation-internal fact,
        // not a user-addressable reference. Both reverse consumers select here.
        // python_binding_rows::EVENT_KINDS stores Assign=1 and Augment=2.
        // Their targets are bare-name declarations. Member operations keep
        // their ordinary nomination path.
        let observed: bool = self.conn().prepare_cached("SELECT NOT EXISTS(SELECT 1 FROM python_member_operations WHERE blob_id=?1 AND callee_reference=?2)
             AND NOT EXISTS(SELECT 1 FROM resolution_binding_events
              WHERE blob_id=?1 AND target=?2 AND kind IN (1,2))
             AND (EXISTS(SELECT 1 FROM python_member_operations WHERE blob_id=?1 AND name_site=?2) OR (EXISTS(SELECT 1 FROM resolution_binding_observations WHERE blob_id=?1 AND reference=?2)
                AND NOT EXISTS(SELECT 1 FROM resolution_binding_slots WHERE blob_id=?1 AND slot=?2)
                AND NOT EXISTS(
                    SELECT 1 FROM resolution_binding_events events INDEXED BY resolution_binding_events_target
                    JOIN temp.python_reverse_evidence seed ON seed.kind='seed'
                      AND seed.blob=events.blob_id AND seed.site=events.authored
                    WHERE events.blob_id=?1 AND events.target=?2)))")?.query_row(
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
    #[cfg(any(test, feature = "test-support"))]
    pub fn python_native_reverse_confirmation(
        &self,
        summary: i64,
        targets: &[CodeUnit],
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancel: &CancellationToken,
    ) -> Result<PythonNativeReverseResult> {
        self.python_reverse_operation(
            &PythonSelectedEnvironment {
                summary,
                python_version,
            },
            targets,
            PythonReverseRequest {
                scope: None,
                limits: PythonReverseLimits {
                    max_sites: usize::MAX,
                },
                session: None,
                cancellation: cancel,
            },
        )
    }

    /// Graph consumers share the reverse inventory's selected-environment loss
    /// evidence, without nominating targets or confirming reverse references.
    /// Returns obligation labels and the callers with unknown placement.
    #[doc(hidden)]
    pub fn python_graph_input_evidence(
        &self,
        environment: &PythonSelectedEnvironment,
        cancellation: &CancellationToken,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let view = PythonReverseView::select(self, environment.summary, cancellation)?;
        view.validate_current_use(self, cancellation)?;
        let mut labels = view.query_obligations;
        for obligation in view.obligations {
            labels.push(obligation.label);
        }
        Ok((labels, view.unplaced))
    }

    /// Classify a selected relative import only when this admitted reference
    /// actually demands that import. The route remains open in either case.
    #[doc(hidden)]
    pub fn python_graph_relative_import_routes(
        &self,
        environment: &PythonSelectedEnvironment,
        answers: &[crate::analyzer::resolution::FactBatchedReferenceAnswer],
    ) -> Result<
        Vec<brokk_bifrost_core::analyzer::usages::inverted_edges::RelativeImportRouteEvidence>,
    > {
        use brokk_bifrost_core::analyzer::usages::inverted_edges::{
            RelativeImportGap, RelativeImportGapKind,
        };
        let Some(first) = answers.first() else {
            return Ok(Vec::new());
        };
        let Some(ordinal) = first.reference().ordinal() else {
            return Ok(Vec::new());
        };
        debug_assert!(
            answers
                .iter()
                .all(|answer| answer.reference().ordinal() == Some(ordinal))
        );
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let workspace_parent_depth = Path::new(mount.persisted_relative_path())
            .parent()
            .expect("source parent")
            .components()
            .count();
        let blob = mount.blob_id();
        let conn = self.ready.inventory.connection();
        let mut statement = conn.prepare_cached(
            "SELECT DISTINCT authored.relative_level,authored.module_segments,json(authored.route),route.state,route.import_site
             FROM python_binding_imports authored
             JOIN resolution_unit_summary_members member ON member.summary_id=?2 AND member.blob_id=authored.blob_id AND member.rel_path=?3
             JOIN python_unit_summary_imports route ON route.summary_id=member.summary_id AND route.member_ordinal=member.member_ordinal AND route.import_site=authored.import_site
             WHERE authored.blob_id=?1
               AND authored.relative_level>0 AND route.importer_container<>'' AND route.target_container=''
               AND route.state IN ('provider_open','relative_context_open')",
        )?;
        let rows = statement.query_map(
            rusqlite::params![blob, environment.summary, mount.persisted_relative_path()],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u32>(4)?,
                ))
            },
        )?;
        let mut routes = Vec::new();
        for row in rows {
            let (level, segments, route, state, site) = row?;
            // The selected packaging root may sit below the analysis root.
            // Only a climb above the workspace itself is outside-workspace.
            if state == "relative_context_open" && workspace_parent_depth >= level as usize {
                continue;
            }
            let (evidence, label) = super::python_demand::import_route_obligation(
                &self.ready,
                environment.summary,
                mount.persisted_relative_path(),
                site,
                &state,
            )?;
            let ResolutionCompletion::Incomplete(reasons) = evidence else {
                unreachable!()
            };
            let matching = answers
                .iter()
                .filter(|answer| {
                    reasons.iter().any(|reason| {
                        answer
                            .answer()
                            .binding()
                            .completion()
                            .contains_reason(*reason)
                    })
                })
                .filter_map(|answer| answer.site_metadata())
                .collect::<Vec<_>>();
            let used = matching.iter().any(|metadata| metadata.site_kind() != brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ModuleReference);
            let mut route: Vec<String> = serde_json::from_str(&route).map_err(|error| {
                StoreError::corrupt(format!("invalid Python import route: {error}"))
            })?;
            route.truncate(segments);
            routes.push((
                mount.persisted_relative_path().to_owned(),
                used.then(|| RelativeImportGap {
                    target: format!("{}{}", ".".repeat(level as usize), route.join(".")),
                    kind: if state == "relative_context_open" {
                        RelativeImportGapKind::OutsideWorkspace
                    } else {
                        RelativeImportGapKind::Absent
                    },
                }),
                label,
            ));
        }
        routes.sort();
        routes.dedup();
        Ok(routes)
    }

    /// Confirm a usage scan with independent, site-scaled caller budgets.
    /// The scan-site limit and cancellation still bound the complete inventory.
    /// A single point-resolution allowance must not cap a multi-file scan.
    pub fn python_reverse_targets_in_scope(
        &self,
        environment: &PythonSelectedEnvironment,
        targets: &[CodeUnit],
        scope: &UsageScanScope<'_>,
        limits: PythonReverseLimits,
    ) -> Result<PythonNativeReverseResult> {
        let cancellation = scope.cancellation().cloned().unwrap_or_default();
        self.python_reverse_operation(
            environment,
            targets,
            PythonReverseRequest {
                scope: Some(scope),
                limits,
                session: None,
                cancellation: &cancellation,
            },
        )
    }

    /// Confirm selected reverse sites within one request's admitted scan scope.
    /// A stop retains explicit unprocessed targets, never empty complete answers.
    pub fn python_reverse_targets(
        &self,
        environment: &PythonSelectedEnvironment,
        targets: &[CodeUnit],
        scope: &UsageScanScope<'_>,
        limits: PythonReverseLimits,
        session: &ResolutionSession,
    ) -> Result<PythonNativeReverseResult> {
        let cancellation = scope.cancellation().cloned().unwrap_or_default();
        self.python_reverse_operation(
            environment,
            targets,
            PythonReverseRequest {
                scope: Some(scope),
                limits,
                session: Some(session),
                cancellation: &cancellation,
            },
        )
    }

    fn python_reverse_operation(
        &self,
        environment: &PythonSelectedEnvironment,
        targets: &[CodeUnit],
        request: PythonReverseRequest<'_>,
    ) -> Result<PythonNativeReverseResult> {
        let PythonSelectedEnvironment {
            summary,
            python_version,
        } = *environment;
        let cancel = request.cancellation;
        if let Some(reason) = request.stop_reason(0) {
            return Ok(PythonNativeReverseResult {
                targets: Vec::new(),
                unavailable: Vec::new(),
                inventory: String::new(),
                query_obligations: Vec::new(),
                nominated_paths: Vec::new(),
                unprocessed: targets
                    .iter()
                    .cloned()
                    .map(|target| PythonNativeReverseUnavailableTarget {
                        target,
                        reason: reason.into(),
                    })
                    .collect(),
            });
        }
        let retained = Cell::new(0usize);
        let truncated = Cell::new(false);
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
        conn.prepare_cached("INSERT INTO temp.python_reverse_operations(mount,operation,blob,site,name_site,form,effect,name_kind,callee_reference,receiver_reference,receiver_slot,possible_replacement)
            SELECT mounts.mount_ordinal,op.id,op.blob_id,op.site,op.name_site,op.form,
                   op.effect,op.name_kind,op.callee_reference,op.receiver_reference,
                   op.receiver_slot,(op.effect<>0 AND (op.name_kind<>0 OR EXISTS(SELECT 1 FROM python_member_operation_names names WHERE names.operation=op.id)))
            FROM temp.selected_resolution_mounts mounts
            JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?1
            JOIN python_member_operations op ON op.blob_id=mounts.blob_id
            WHERE mounts.storage_language='python'")?.execute(
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
            let changed = conn.prepare_cached("UPDATE temp.python_reverse_operations SET patch_target=?3 WHERE mount=?1 AND operation=?2")?.execute( params![mount,operation,target])?;
            self.ready
                .inventory
                .account_committed_request_changes(changed as u64);
        }
        let view = PythonReverseView::select(self, summary, cancel)?;
        view.validate_current_use(self, cancel)?;
        let mut output = view.inventory.join("\n");
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
        let mut result = PythonNativeReverseResult {
            inventory: output,
            query_obligations: view.query_obligations.clone(),
            nominated_paths: Vec::new(),
            targets: Vec::new(),
            unavailable: Vec::new(),
            unprocessed: Vec::new(),
        };
        for (target_index, target) in targets.iter().enumerate() {
            view.validate_current_use(self, cancel)?;
            let stopped = request.stop_reason(retained.get());
            if let Some(reason) = stopped {
                result
                    .unprocessed
                    .extend(targets[target_index..].iter().cloned().map(|target| {
                        PythonNativeReverseUnavailableTarget {
                            target,
                            reason: reason.into(),
                        }
                    }));
                break;
            }
            let hooks = PythonReverseHooks {
                operation: self,
                view: &view,
                cancellation: cancel,
                coordinate: None,
                target,
            };
            let cleared = conn
                .prepare_cached("DELETE FROM temp.python_reverse_evidence")?
                .execute([])?;
            self.ready
                .inventory
                .account_committed_request_changes(cleared as u64);
            let mut output = format!(
                "target {} {}\n",
                selected_path_key(target.source().rel_path()),
                target.identifier()
            );
            let coordinates = hooks.coordinates(target, cancel)?;
            if coordinates.is_empty() {
                if target.is_module()
                    && self
                        .mount_table()
                        .mount_for_path("python", &selected_path_key(target.source().rel_path()))?
                        .is_none()
                {
                    result.unavailable.push(PythonNativeReverseUnavailableTarget {
                        target: target.clone(),
                        reason: "Python module target has no selected source declaration; namespace packages are unsupported".into(),
                    });
                    continue;
                }
                result
                    .unavailable
                    .push(PythonNativeReverseUnavailableTarget {
                        target: target.clone(),
                        reason: format!(
                            "Python reverse target unavailable: {}",
                            target.fq_name_str()
                        ),
                    });
                continue;
            }
            let semantics = coordinates
                .iter()
                .map(|coordinate| coordinate.0)
                .collect::<Vec<_>>();
            let semantic = semantics[0];
            let field_slot = if target.is_field() {
                self.python_module_field(&semantics, cancel)?
            } else {
                None
            };
            let mut locators = Vec::new();
            for coordinate in coordinates {
                let exact = PythonReverseHooks {
                    operation: self,
                    view: &view,
                    cancellation: cancel,
                    coordinate: Some(coordinate),
                    target,
                };
                let Some(candidates) = nominate_reverse_target(self, &exact, target, &[], cancel)?
                else {
                    return Err(StoreError::new(
                        "Python reverse authored target unavailable",
                    ));
                };
                locators.extend(candidates.locators);
            }
            // Capture the target's namespace relation before the construction
            // family adds its own class/subclass exposures to the evidence.
            let receivers = hooks.receiver_candidates()?;
            locators.extend(receivers.keys().cloned());
            let constructions = self.python_construction_family(
                &view,
                target,
                &semantics,
                &request,
                python_version,
            )?;
            locators.extend(constructions.calls.keys().cloned());
            locators.retain(|locator| {
                request.scope.is_none_or(|scope| {
                    scope.allows(&ProjectFile::new(
                        self.ready.project.root(),
                        locator.relative_path(),
                    ))
                })
            });
            locators.sort();
            locators.dedup();
            result.nominated_paths.extend(
                locators
                    .iter()
                    .map(|locator| locator.relative_path().to_owned()),
            );
            let candidates = super::reverse_nomination::ReverseCandidateSet {
                locators,
                names: Vec::new(),
            };
            output.push_str(&format!("nominations={}\n", candidates.locators.len()));
            for locator in &candidates.locators {
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
            let mut answer = PythonNativeReverseTarget {
                target: target.clone(),
                semantic,
                authored_definitions: semantics.len(),
                semantics,
                field_slot,
                sites: Vec::new(),
                complete: constructions.obligations.is_empty(),
                obligations: view
                    .obligations
                    .iter()
                    .filter(|obligation| {
                        obligation.caller.as_ref().is_none_or(|path| {
                            request.scope.is_none_or(|scope| {
                                scope.allows(&ProjectFile::new(self.ready.project.root(), path))
                            })
                        })
                    })
                    .map(|obligation| obligation.label.clone())
                    .collect(),
                confirmation_sql: None,
                confirmation_elapsed: std::time::Duration::ZERO,
                receipt: output,
                proof: reverse::ReverseProofBatch::new(semantic, Vec::new()),
            };
            answer
                .obligations
                .extend(constructions.obligations.iter().cloned());
            // Required contexts are selected before checking surviving hits,
            // including admitted callers with no ordinary references.
            let contexts = conn.prepare_cached("SELECT mounts.mount_ordinal,mounts.blob_id,mounts.persisted_relative_path FROM temp.selected_resolution_mounts mounts JOIN resolution_unit_summary_members members ON members.summary_id=?1 AND members.blob_id=mounts.blob_id AND members.rel_path=mounts.persisted_relative_path WHERE mounts.storage_language='python' ORDER BY mounts.mount_ordinal")?
                .query_map([summary], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (mount, blob, path) in contexts {
                if request.scope.is_some_and(|scope| {
                    !scope.allows(&ProjectFile::new(self.ready.project.root(), &path))
                }) {
                    continue;
                }
                let selected = ReverseContextWitness::new(self, mount, blob);
                let index = answer
                    .proof
                    .extend_contexts(vec![reverse::ReverseContextId {
                        selected: selected.clone(),
                        view: view.context.clone(),
                    }])[0];
                for obligation in view
                    .obligations
                    .iter()
                    .filter(|obligation| obligation.affects(&path))
                {
                    if matches!(
                        obligation.coverage,
                        PythonReverseCoverage::CandidatesAndEnumeration
                    ) {
                        let handle = answer.proof.evidence.binding.record(
                            reverse::ReverseSubject::Context(selected.clone()),
                            reverse::ReverseEvidenceOrigin::Inventory,
                            obligation.completion.clone(),
                        );
                        assert!(
                            answer
                                .proof
                                .obligation_contexts
                                .insert(handle, index)
                                .is_none()
                        );
                    }
                    let handle = answer.proof.evidence.enumeration.record(
                        reverse::ReverseSubject::Context(selected.clone()),
                        reverse::ReverseEvidenceOrigin::Inventory,
                        obligation.completion.clone(),
                    );
                    assert!(
                        answer
                            .proof
                            .obligation_contexts
                            .insert(handle, index)
                            .is_none()
                    );
                }
            }
            // TEMP exposure rows are nomination evidence, never binding proof.
            // Keep their independent provenance on the existing three axes.
            let mut receipts =
                reverse::ReverseProofBatch::new(semantic, answer.proof.required.clone());
            let exposures = conn.prepare_cached("SELECT kind,blob FROM temp.python_reverse_evidence ORDER BY kind,container,name,scope,blob,site")?
                .query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (kind, blob) in exposures {
                for (index, context) in receipts
                    .required
                    .iter()
                    .enumerate()
                    .filter(|(_, context)| blob < 0 || context.selected.blob == blob)
                {
                    let handle = receipts.evidence.enumeration.record(
                        reverse::ReverseSubject::Context(context.selected.clone()),
                        if matches!(kind.as_str(), "named" | "module" | "star") {
                            reverse::ReverseEvidenceOrigin::Import
                        } else {
                            reverse::ReverseEvidenceOrigin::Nomination
                        },
                        ResolutionCompletion::Complete,
                    );
                    assert!(receipts.obligation_contexts.insert(handle, index).is_none());
                }
            }
            for locator in &candidates.locators {
                let mount = self
                    .mount_table()
                    .mount_for_path("python", locator.relative_path())?
                    .expect("selected nomination");
                let selected = ReverseContextWitness::new(
                    self,
                    mount.ordinal().get(),
                    self.ready
                        .inventory
                        .mount_record_by_ordinal(mount.ordinal())?
                        .blob_id(),
                );
                let index = receipts
                    .required
                    .iter()
                    .position(|context| context.selected == selected)
                    .expect("nomination caller has independent context");
                let subject = reverse::ReverseSubject::Site(locator.clone(), selected);
                let operation: Option<(u32,u32)> = conn.prepare_cached("SELECT op.name_kind,op.possible_replacement FROM temp.python_reverse_operations op WHERE op.mount=?1 AND op.name_site=?2")?.query_row( params![mount.ordinal().get(),locator.source_site().expect("Python source nomination").get()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
                let metadata = receipts.evidence.metadata.record(
                    subject.clone(),
                    reverse::ReverseEvidenceOrigin::Projection,
                    ResolutionCompletion::Complete,
                );
                assert!(
                    receipts
                        .obligation_contexts
                        .insert(metadata, index)
                        .is_none()
                );
                if operation.is_some() {
                    let binding = receipts.evidence.binding.record(
                        subject,
                        reverse::ReverseEvidenceOrigin::Nomination,
                        ResolutionCompletion::Complete,
                    );
                    assert!(
                        receipts
                            .obligation_contexts
                            .insert(binding, index)
                            .is_none()
                    );
                }
            }
            reverse::append_reverse_proof(&mut answer.proof, receipts);
            let before = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
            let started = std::time::Instant::now();
            let mut cursor = 0;
            let files = std::iter::from_fn(|| {
                if cursor == candidates.locators.len() || retained.get() >= request.limits.max_sites
                {
                    return None;
                }
                let start = cursor;
                cursor += 1;
                while cursor < candidates.locators.len()
                    && candidates.locators[cursor].relative_path()
                        == candidates.locators[start].relative_path()
                {
                    cursor += 1;
                }
                Some(reverse::ReverseFile {
                    range: start..cursor,
                    payload: candidates.locators[start..cursor].to_vec(),
                })
            });
            let progress = reverse::confirm_reverse_files(
                files,
                0,
                &mut PythonReverseFiles {
                    operation: self,
                    view: &view,
                    python_version,
                    cancellation: cancel,
                    target: &mut answer,
                    session: request.session,
                    retained: &retained,
                    truncated: &truncated,
                    max_sites: request.limits.max_sites,
                    constructions: &constructions,
                    receivers: &receivers,
                },
            )?;
            let scan_stopped = truncated.get()
                || (retained.get() >= request.limits.max_sites
                    && progress.next < candidates.locators.len());
            let stopped = !matches!(progress.stopped, reverse::ReverseBlobControl::Continue)
                || scan_stopped
                || request.session.is_some_and(|session| {
                    !matches!(session.finish(()), BoundedResolution::Complete { .. })
                });
            if scan_stopped {
                answer.obligations.push("python_reverse_scan_limit".into());
            }
            if stopped {
                answer.complete = false;
                if request.session.is_some_and(|session| {
                    !matches!(session.finish(()), BoundedResolution::Complete { .. })
                }) {
                    answer
                        .obligations
                        .push("python_reverse_session_stopped".into());
                }
            }
            if answer.proof.required.is_empty() {
                answer.complete = false;
                answer
                    .obligations
                    .push("python_reverse_no_required_context".into());
            }
            for (facet, evidence) in [
                ("enumeration", &answer.proof.evidence.enumeration),
                ("binding", &answer.proof.evidence.binding),
                ("metadata", &answer.proof.evidence.metadata),
            ] {
                let completion = evidence.completion_with_poll(&mut || cancel.is_cancelled());
                if completion != Some(ResolutionCompletion::Complete) {
                    answer.complete = false;
                    answer.obligations.push(match completion {
                        Some(completion) => {
                            format!("python_reverse_{facet}_incomplete:{completion:?}")
                        }
                        None => format!("python_reverse_{facet}_cancelled"),
                    });
                }
            }
            if !answer.complete {
                if cancel.is_cancelled() {
                    answer.obligations.push("python_reverse_cancelled".into());
                } else if cancel.soft_deadline_passed() {
                    answer
                        .obligations
                        .push("python_reverse_time_stopped".into());
                }
            }
            answer.obligations.sort();
            answer.obligations.dedup();
            answer.confirmation_elapsed = started.elapsed();
            answer.confirmation_sql = before
                .zip(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows())
                .map(|(before, after)| (after.0 - before.0, after.1 - before.1));
            result.targets.push(answer);
            if stopped {
                // Later targets carry the cause of the stop (scan limit,
                // session, time, cancellation) when the request names one.
                let reason = request
                    .stop_reason(retained.get())
                    .unwrap_or("python_reverse_batch_stopped");
                result
                    .unprocessed
                    .extend(targets[target_index + 1..].iter().cloned().map(|target| {
                        PythonNativeReverseUnavailableTarget {
                            target,
                            reason: reason.into(),
                        }
                    }));
                break;
            }
        }
        result.nominated_paths.sort();
        result.nominated_paths.dedup();
        view.validate_current_use(self, cancel)?;
        Ok(result)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PythonModuleField {
    pub(super) path: String,
    slot: u32,
    name: String,
}

struct PythonReverseAnswer {
    answer: FactResolutionAnswer,
    // A module field names a storage slot, independently of its current value.
    field_identity: Option<bool>,
    label_open: bool,
    obligations: Vec<String>,
    receiver_relation: Option<reverse::ReverseTargetRelation>,
}

// The shared lifecycle owns ordering; these hooks supply the selected Python
// environment and one bounded forward operation per caller slice.
struct PythonReverseLifecycle<'a, 'store, 'input> {
    constructions: &'a construction::ConstructionFamily,
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    summary: i64,
    python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    cancellation: &'a CancellationToken,
    session: &'a ResolutionSession,
    field_slot: Option<&'a PythonModuleField>,
    targets: &'a [SemanticId],
    target_is_field: bool,
    target_name: &'a str,
    profile: super::python_lexical::PythonBindingProfile,
    receivers: &'a HashMap<SelectedSemanticLocator, PythonReverseReceiver>,
}
impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn python_module_field(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Option<PythonModuleField>> {
        let mut field = None;
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = definition.ordinal() else {
                return Ok(None);
            };
            let mount = self
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let authored: Option<u32> = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT source_site FROM resolution_semantic_sites
                 WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='definition'",
                )?
                .query_row(params![mount.blob_id(), definition.local_key()], |row| {
                    row.get(0)
                })
                .optional()?;
            let Some(rows) = super::super::python_binding_rows::PythonBindingRows::load(
                self.ready.inventory.connection(),
                &self.ready.store.cache_budget,
                mount.blob_id(),
                None,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some(event) = rows.events.iter().find(|event| {
                event.authored == authored && authored.is_some()
                    && matches!(event.kind,
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Assign
                        | brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Augment
                        | brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Annotation)
            }) else { return Ok(None); };
            let slot = rows
                .slots
                .iter()
                .find(|slot| slot.slot == event.slot)
                .expect("field event has a retained slot");
            if !rows
                .scopes
                .iter()
                .any(|scope| scope.scope == slot.scope && scope.parent.is_none())
            {
                return Ok(None);
            }
            let current = PythonModuleField {
                path: mount.persisted_relative_path().to_owned(),
                slot: slot.slot,
                name: slot.name.clone(),
            };
            if field.as_ref().is_some_and(|previous| previous != &current) {
                return Ok(None);
            }
            field = Some(current);
        }
        Ok(field)
    }
}

pub(super) struct PythonFieldIdentity<'a, 'store, 'input> {
    pub operation: &'a SelectedResolutionOperation<'store, 'input>,
    pub summary: i64,
    pub profile: super::python_lexical::PythonBindingProfile,
    pub cancellation: &'a CancellationToken,
    pub session: &'a ResolutionSession,
}

impl PythonReverseLifecycle<'_, '_, '_> {
    // A keyword can remain open only for an attribute of a possible callee class.
    fn open_label_matches_owner<P: crate::analyzer::resolution::DemandRootProvider + ?Sized>(
        &self,
        operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        provider: &mut P,
        reference: SemanticId,
        label: &str,
        possible_classes: &[SemanticId],
        callee_complete: bool,
    ) -> Result<bool> {
        if !self.target_is_field || label != self.target_name {
            return Ok(false);
        }
        if !callee_complete {
            return Ok(true);
        }
        let candidates = super::python_members::class_attribute_candidates(
            &self.operation.ready,
            operation,
            provider,
            reference,
            possible_classes,
            label,
            self.cancellation,
        )?;
        Ok(candidates.is_none_or(|candidates| {
            candidates
                .iter()
                .any(|target| self.targets.contains(target))
        }))
    }

    fn field_identity(
        &self,
        locator: &SelectedSemanticLocator,
        forward: &FactResolutionAnswer,
    ) -> Result<Option<bool>> {
        let Some(field) = self.field_slot else {
            return Ok(None);
        };
        PythonFieldIdentity {
            operation: self.operation,
            summary: self.summary,
            profile: self.profile,
            cancellation: self.cancellation,
            session: self.session,
        }
        .matches(locator, forward, field)
    }
}

impl PythonFieldIdentity<'_, '_, '_> {
    pub(super) fn matches(
        &self,
        locator: &SelectedSemanticLocator,
        forward: &FactResolutionAnswer,
        field: &PythonModuleField,
    ) -> Result<Option<bool>> {
        use super::demand_closure::{
            RankedLexicalTier, Read, RouteEdgeTier, select_lexical_route_starts,
        };
        use super::python_lexical::{self, PythonBindingProofs};
        use crate::analyzer::resolution::temporal_binding::SessionBudget;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionBindingEventKind, ResolutionScopeId,
        };
        use std::cell::RefCell;

        let mount = self
            .operation
            .mount_table()
            .mount_for_path("python", locator.relative_path())?
            .expect("selected Python field observation");
        let blob = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?
            .blob_id();
        let site = locator
            .source_site()
            .unwrap_or_else(|| {
                forward
                    .site_metadata()
                    .expect("positioned Python field reference")
                    .site()
            })
            .get();
        let conn = self.operation.ready.inventory.connection();
        // Reaching values may be cyclic or unsupported without changing the
        // lexical slot. Preserve gaps in the scope/binder route itself.
        if let ResolutionCompletion::Incomplete(reasons) = forward.binding().completion() {
            for reason in reasons.iter() {
                let (ResolutionIncompleteReason::UnsupportedSemantic(reason)
                | ResolutionIncompleteReason::ReceiverSubclassObligation(reason)) = reason
                else {
                    continue;
                };
                let Some(ordinal) = reason.ordinal() else {
                    continue;
                };
                let reason_blob = self
                    .operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                    .blob_id();
                let origin = conn
                    .prepare_cached(
                        "SELECT origin FROM resolution_gap_reasons WHERE blob_id=?1 AND reason=?2",
                    )?
                    .query_row(params![reason_blob, reason.local_key()], |row| {
                        row.get::<_, i64>(0)
                    })
                    .optional()?;
                if origin.is_some_and(|origin| matches!(
                    super::super::resolution_prepare::resolution_rows::gap_origin_from_code(origin),
                    crate::analyzer::resolution::LoweringGapOrigin::MissingBinder
                    | crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference
                    | crate::analyzer::resolution::LoweringGapOrigin::UnsupportedActivation(_)
                    | crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder
                        | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedRoute
                    )
                )) {
                    return Ok(None);
                }
            }
        }
        let Some(rows) = super::super::python_binding_rows::PythonBindingRows::load(
            conn,
            &self.operation.ready.store.cache_budget,
            blob,
            None,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let conditional_imports = super::python_demand::conditional_imports(
            &self.operation.ready,
            self.summary,
            &rows,
            locator.relative_path(),
            blob,
        )?;
        // The imported name token is a provider demand, before the local alias
        // write. Reads of that alias use the ordinary lexical selection below.
        let imported: Vec<u32> = conn
            .prepare_cached(
                "SELECT DISTINCT import_site FROM resolution_root_import_demands
             WHERE blob_id=?1 AND target_reference=?2",
            )?
            .query_map(params![blob, site], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if !imported.is_empty() {
            if imported
                .iter()
                .all(|site| conditional_imports.contains(site))
            {
                return self.imported_identity(
                    forward,
                    field,
                    blob,
                    locator.relative_path(),
                    &imported,
                );
            }
            return Ok(None);
        }
        // Read the lookup spelling from the structured identity. An import
        // alias may differ from its provider's field name.
        let name: Option<String> = conn.prepare_cached("SELECT name.spelling FROM resolution_sites site
             JOIN resolution_semantic_sites semantic ON semantic.blob_id=site.blob_id
              AND semantic.source_site=site.site AND semantic.semantic_role='reference'
             JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id
              AND lookup.semantic_key=semantic.semantic_key
             JOIN resolution_identities name ON name.id=lookup.identity_id
             WHERE site.blob_id=?1 AND site.site=?2 AND site.role=0 AND site.site_kind=?3
              AND NOT EXISTS(SELECT 1 FROM python_member_operations op
               WHERE op.blob_id=site.blob_id AND op.name_site=site.site)")?.query_row(
            params![blob, site, super::super::resolution_prepare::resolution_rows::site_kind_code(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ValueReference,
            )], |row| row.get(0),
        ).optional()?;
        let Some(name) = name else {
            return Ok(None);
        };
        let Some(state) = python_lexical::lexical_selection(
            &rows,
            site,
            &name,
            self.profile,
            PythonBindingProofs {
                conditional_imports,
                ..Default::default()
            },
        ) else {
            return Ok(None);
        };
        let start = ResolutionScopeId::new(state.start_scope);
        let state = RefCell::new(state);
        let selected_slot = Cell::new(None);
        let ambiguous = Cell::new(false);
        let mut completion = ResolutionCompletion::Complete;
        let selection = select_lexical_route_starts::<u32, (), _>(
            start,
            |scope| {
                Ok(
                    python_lexical::lexical_parent(&state.borrow(), &rows, scope.get())
                        .map(ResolutionScopeId::new),
                )
            },
            |scope, _| {
                if !self.session.scope_step() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let mut state = state.borrow_mut();
                let slot = python_lexical::lexical_slot(&state, &rows, scope.get());
                if let Some(slot) = slot {
                    let module = rows
                        .scopes
                        .iter()
                        .any(|row| row.scope == scope.get() && row.parent.is_none());
                    // Ordered class cells still need their normal visibility
                    // proof. Module and whole-function cells have stable storage
                    // identity regardless of the number of reaching writers.
                    if !module && !slot.whole_scope {
                        python_lexical::lexical_tier(
                            &mut state,
                            &rows,
                            scope.get(),
                            &mut SessionBudget {
                                session: self.session,
                                cancellation: self.cancellation,
                            },
                        );
                    }
                    if module
                        || slot.whole_scope
                        || (!state.selection.open
                            && state.selection.residual.is_empty()
                            && state.selection.unbound.is_empty()
                            && !state.selection.selected.is_empty())
                    {
                        selected_slot.set(Some(slot.slot));
                    } else if state.selection.open
                        || !state.selection.selected.is_empty()
                        || !state.selection.unbound.is_empty()
                    {
                        ambiguous.set(true);
                    }
                }
                Ok(Read::ready(vec![Ok(RankedLexicalTier {
                    rank: 0,
                    tier: RouteEdgeTier {
                        blocks_fallback: selected_slot.get().is_some() || ambiguous.get(),
                        ..Default::default()
                    },
                    providers: Vec::new(),
                })]))
            },
            |_, _| {
                selected_slot.get().is_none()
                    && !ambiguous.get()
                    && python_lexical::outer_can_compete(&state.borrow())
            },
            |_, _| false,
            &mut completion,
            self.cancellation,
        )?;
        if !matches!(selection, Read::Ready { .. }) || state.borrow().selection.stopped.is_some() {
            return Ok(None);
        }
        let Some(slot) = selected_slot.get() else {
            return Ok(None);
        };
        let matches_target = locator.relative_path() == field.path && slot == field.slot;
        if !matches_target
            && rows
                .events
                .iter()
                .any(|event| event.slot == slot && event.kind == ResolutionBindingEventKind::Import)
        {
            // Select the import event with the same chronology and scope rules
            // as value resolution, without treating the import cell as the field.
            let mut state = state.borrow_mut();
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
                || state.selection.open
                || !state.selection.residual.is_empty()
                || !state.selection.unbound.is_empty()
                || state.selection.selected.is_empty()
                || !state.selection.selected.iter().all(|selected| {
                    rows.events.iter().any(|event| {
                        event.event == selected.occurrence
                            && event.kind == ResolutionBindingEventKind::Import
                    })
                })
            {
                return Ok(None);
            }
            let imported = state
                .selection
                .selected
                .iter()
                .map(|selected| {
                    rows.imports
                        .iter()
                        .find(|import| {
                            rows.events.iter().any(|event| {
                                event.event == selected.occurrence
                                    && Some(event.event) == import.binding_event
                            })
                        })
                        .expect("selected import event retains its route")
                        .import_site
                        .get()
                })
                .collect::<Vec<_>>();
            return self.imported_identity(
                forward,
                field,
                blob,
                locator.relative_path(),
                &imported,
            );
        }
        // Bare builtin spellings can still fall through before the module cell
        // is initialized. A successful from-import has no builtin fallback.
        if brokk_bifrost_python::intrinsics::builtin(&field.name).is_some() {
            return Ok(None);
        }
        Ok(Some(matches_target))
    }

    fn imported_identity(
        &self,
        forward: &FactResolutionAnswer,
        field: &PythonModuleField,
        caller_blob: i64,
        caller: &str,
        imports: &[u32],
    ) -> Result<Option<bool>> {
        // Only temporal value-selection openness is discharged here. Provider,
        // namespace, activation and binder obligations are independent premises.
        if let ResolutionCompletion::Incomplete(reasons) = forward.binding().completion()
            && reasons.iter().any(|reason| {
                !matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(semantic) | ResolutionIncompleteReason::ReceiverSubclassObligation(semantic)
                    if self.operation.ready.context_identities.named_reason(*semantic)
                        .is_some_and(|(kind, _)| kind == "python_lexical_selection_open"))
            })
        {
            return Ok(None);
        }
        // Establish the imported slot before comparing it with this reverse
        // target. Another proven slot is a complete exclusion, even if that
        // slot's reaching values are open too.
        let Some(selected) = self
            .operation
            .python_module_field(forward.binding().targets(), self.cancellation)?
        else {
            return Ok(None);
        };
        let matches_target = &selected == field;
        let field = &selected;
        // The slot must belong to this import's admitted provider. Re-export
        // routes retain their own closure obligations instead of borrowing a
        // later module's initialized cell across an unbound intermediate path.
        for site in imports {
            let provider_matches: Option<bool> = self.operation.ready.inventory.connection().prepare_cached("SELECT MIN(provider_member.rel_path=?5 AND imports.form='from')
                 FROM python_unit_summary_imports imports
                 JOIN resolution_unit_summary_members caller ON caller.summary_id=imports.summary_id
                  AND caller.member_ordinal=imports.member_ordinal
                 JOIN python_unit_summary_providers provider ON provider.summary_id=imports.summary_id
                  AND provider.container_path=imports.target_container
                  AND provider.state IN ('selected','alternative')
                 JOIN resolution_unit_summary_members provider_member ON provider_member.summary_id=provider.summary_id
                  AND provider_member.member_ordinal=provider.member_ordinal
                 WHERE imports.summary_id=?1 AND caller.blob_id=?2 AND caller.rel_path=?3 AND imports.import_site=?4")?.query_row(
                params![self.summary, caller_blob, caller, site, field.path], |row| row.get(0),
            )?;
            if provider_matches != Some(true) {
                return Ok(None);
            }
        }
        let mount = self
            .operation
            .mount_table()
            .mount_for_path("python", &field.path)?
            .expect("selected module field provider");
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let Some(rows) = super::super::python_binding_rows::PythonBindingRows::load(
            self.operation.ready.inventory.connection(),
            &self.operation.ready.store.cache_budget,
            record.blob_id(),
            None,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let slot = rows
            .slots
            .iter()
            .find(|slot| slot.slot == field.slot)
            .expect("selected field retains its slot");
        // The successful import must have an initialized provider binding.
        // Unknown stars cannot supply a complete alternative inventory.
        if rows.import_positions.iter().any(|(site, scope, _)| *scope == slot.scope
            && rows.imports.iter().any(|import| import.import_site.get() == *site
                && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star))
        { return Ok(None); }
        let mut state = super::python_lexical::module_selection(
            &rows,
            slot.scope,
            &field.name,
            self.profile,
            Default::default(),
        );
        super::python_lexical::lexical_tier(
            &mut state,
            &rows,
            slot.scope,
            &mut crate::analyzer::resolution::temporal_binding::SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            },
        );
        if state.selection.stopped.is_some()
            || state.selection.selected.is_empty()
            || !state.selection.residual.is_empty()
            || !state.selection.unbound.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(matches_target))
    }
}

impl<'store, 'input> reverse::ReverseLifecycle for PythonReverseLifecycle<'_, 'store, 'input> {
    type Answer = PythonReverseAnswer;
    type Limit = std::convert::Infallible;
    type Prepared = SelectedResolutionContextSet;
    type Scoped<'a>
        = PythonReverseLifecycle<'a, 'store, 'input>
    where
        Self: 'a;
    fn prepare(
        &mut self,
        _: &[&SelectedSemanticLocator],
    ) -> Result<reverse::ReverseBatch<Self::Prepared, Self::Limit>> {
        Ok(reverse::ReverseBatch::Ready(empty_contexts_for(
            self.operation.mount_table(),
            &ResolutionCompletion::Complete,
            &selected_mount_lookup(self.operation.mount_table()),
            self.operation.ready.context_identities.clone(),
        )?))
    }
    fn validate(
        &mut self,
        prepared: &Self::Prepared,
    ) -> Result<reverse::ReverseBatch<SelectedResolutionContextInputs, Self::Limit>> {
        Ok(
            match self.operation.prepare_context_in_session(
                prepared.clone(),
                self.cancellation,
                &SelectedResolutionContextMetrics,
                self.session,
            )? {
                SelectedResolutionContextValidationOutcome::Ready(context) => {
                    reverse::ReverseBatch::Ready(context)
                }
                SelectedResolutionContextValidationOutcome::Cancelled => {
                    reverse::ReverseBatch::Cancelled {
                        stage: reverse::ReverseCancellationStage::Prepare,
                        completion: cancelled_completion(),
                    }
                }
            },
        )
    }
    fn with_scope<'a, T>(
        &'a mut self,
        _: &'a Self::Prepared,
        run: impl FnOnce(&mut Self::Scoped<'a>) -> Result<reverse::ReverseBatch<T, Self::Limit>>,
    ) -> Result<reverse::ReverseBatch<T, Self::Limit>> {
        run(&mut PythonReverseLifecycle {
            constructions: self.constructions,
            operation: self.operation,
            summary: self.summary,
            python_version: self.python_version,
            cancellation: self.cancellation,
            session: self.session,
            field_slot: self.field_slot,
            targets: self.targets,
            target_is_field: self.target_is_field,
            target_name: self.target_name,
            profile: self.profile,
            receivers: self.receivers,
        })
    }
    fn finish(
        &mut self,
        reports: Vec<reverse::ReverseSessionReport<Self::Answer>>,
    ) -> reverse::ReverseSessionOutcome<Self::Answer, Self::Limit> {
        Ok(reverse::ReverseBatch::Ready(reports))
    }
}
impl reverse::ReverseScopedLifecycle for PythonReverseLifecycle<'_, '_, '_> {
    type Answer = PythonReverseAnswer;
    type Limit = std::convert::Infallible;
    fn blueprint(
        &mut self,
        context: SelectedResolutionContextInputs,
    ) -> Result<reverse::ReverseBatch<SelectedFactOperationBlueprint, Self::Limit>> {
        self.operation
            .ready
            .reverse_blueprint_in_session(context, self.cancellation, self.session)
    }
    fn register(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
    ) -> Result<reverse::ReverseBatch<(), Self::Limit>> {
        self.operation
            .ready
            .reverse_register_in_session(blueprint, self.cancellation, self.session)
    }
    fn locate(
        &mut self,
        locator: &SelectedSemanticLocator,
    ) -> Result<reverse::ReverseBatch<LocatedSemantics, Self::Limit>> {
        if let Some(receiver) = self.receivers.get(locator) {
            // A wholly unknown name need not have a locatable reference. Its
            // receiver is the independent binding authority for this relation.
            return Ok(reverse::ReverseBatch::Ready(LocatedSemantics::Found(vec![
                receiver.reference,
            ])));
        }
        self.operation
            .ready
            .reverse_locate_in_session(locator, self.cancellation, self.session)
    }
    fn with_evaluator<T>(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
        run: impl FnOnce(
            &mut dyn reverse::ReverseSessionEvaluator<Answer = Self::Answer, Limit = Self::Limit>,
        ) -> Result<reverse::ReverseBatch<T, Self::Limit>>,
    ) -> Result<reverse::ReverseBatch<T, Self::Limit>> {
        self.operation.with_python_forward_operation(
            self.summary,
            self.python_version,
            blueprint,
            self.session,
            self.cancellation,
            |operation, provider, _, _, _, external_imports, _, mutations| {
                run(&mut reverse::ReverseEvaluatorFn {
                    marker: std::marker::PhantomData,
                    run: |locator: &SelectedSemanticLocator, semantic: SemanticId| {
                        if !self.session.scope_step() || self.cancellation.is_cancelled() {
                            // ResolutionSession::finish owns the stop classification:
                            // scope-step exhaustion becomes Exceeded from the session's
                            // stop state, even though this stage reports Cancelled.
                            return Ok(reverse::ReverseBatch::Cancelled {
                                stage: reverse::ReverseCancellationStage::Projection,
                                completion: cancelled_completion(),
                            });
                        }
                        external_imports.borrow_mut().requested_reference = Some(semantic);
                        let receiver = self.receivers.get(locator);
                        let mut receiver_relation = receiver.map(|_| reverse::ReverseTargetRelation::Undecided);
                        Ok(
                            match operation.resolve_reference_by_demand(semantic, provider)? {
                                FactDemandResolution::Ready(answer) => {
                                    let answer = self.constructions.project(locator, *answer);
                                    let (named_argument, possible_classes, callee_complete) = super::python_demand::project_python_named_argument(
                                        &self.operation.ready, operation, provider, semantic,
                                        self.summary, self.cancellation, self.session, mutations,
                                    )?;
                                    let label_open = if matches!(named_argument, Some(super::native_units::SelectedNativeNamedArgument::Incomplete(_))) {
                                        match operation.named_argument_label_for_reference(semantic)? {
                                            crate::analyzer::resolution::NamedArgumentLabelRead::Found(label) => {
                                                self.open_label_matches_owner(operation, provider, semantic, &label.spelling, &possible_classes, callee_complete)?
                                            }
                                            _ => false,
                                        }
                                    } else { false };
                                    let field_identity = match named_argument {
                                        Some(super::native_units::SelectedNativeNamedArgument::Resolved(parameter, _)) => {
                                            Some(self.targets.contains(&parameter))
                                        }
                                        Some(super::native_units::SelectedNativeNamedArgument::Absent(_)) => Some(false),
                                        Some(super::native_units::SelectedNativeNamedArgument::Incomplete(_)) => {
                                            (!label_open).then_some(false)
                                        }
                                        None => self.field_identity(locator, &answer)?,
                                    };
                                    let completion = answer.call_target_completion();
                                    let external = super::python_demand::selected_external_imports(external_imports, semantic);
                                    let mut external_receiver_excluded = false;
                                    // A complete external boundary is outside the selected
                                    // environment. Re-exports remain a query obligation.
                                    // The unique-import proof rejects competing writers,
                                    // open namespaces and unresolved guards. An unacquired
                                    // provider alone can leave temporal regions open;
                                    // that openness belongs to the environment obligation.
                                    if answer.binding().targets().is_empty()
                                        && let [selected] = external.as_slice()
                                        && selected.boundary_is_unique
                                        && selected.identity_is_unique
                                        && selected.remaining_member_path.len() == usize::from(receiver.is_none())
                                        && !selected.selection.is_empty()
                                        && selected.selection.iter().all(|state| {
                                            state.completion == ResolutionCompletion::Complete
                                        })
                                    {
                                        receiver_relation = Some(reverse::ReverseTargetRelation::Excluded);
                                        external_receiver_excluded = true;
                                    }

                                    if let Some(receiver) = receiver {
                                        debug_assert_eq!(semantic, receiver.reference);
                                    if answer.binding().completion() == &ResolutionCompletion::Complete
                                        && let [target] = answer.binding().targets()
                                    {
                                        if receiver.owners.contains(target) {
                                            receiver_relation = Some(reverse::ReverseTargetRelation::Matches);
                                        } else {
                                            let mut namespace = super::python_members::is_class(&self.operation.ready, *target)?;
                                            if let Some(ordinal) = target.ordinal() {
                                                let mount = self.operation.mount_table().mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                                                let blob = self.operation.ready.inventory.mount_record_by_ordinal(mount.ordinal())?.blob_id();
                                                namespace |= super::python_demand::module_declaration_site(self.operation.ready.inventory.connection(), blob)?
                                                    .is_some_and(|site| crate::analyzer::resolution::mounted_site_semantic(mount.fragment(), site) == *target);
                                            }
                                            // A cell or parameter identity is not an exact object.
                                            if namespace {
                                                receiver_relation = Some(reverse::ReverseTargetRelation::Excluded);
                                            }
                                        }
                                    }
                                    }
                                    let mut obligations = named_reason_details(&self.operation.ready,&completion)?.into_iter().map(|(kind,detail)|format!("{kind}:{detail}")).collect::<Vec<_>>();
                                    if let ResolutionCompletion::Incomplete(reasons) = &completion {
                                        for reason in reasons.iter() {
                                            let label = match reason {
                                                ResolutionIncompleteReason::UnsupportedSemantic(semantic) | ResolutionIncompleteReason::ReceiverSubclassObligation(semantic) => operation.service_reason_details(*semantic).map(|(name,_)| name.to_owned()).unwrap_or_else(|| "unsupported_semantic".into()),
                                                ResolutionIncompleteReason::OpenBoundary {..} => "open_boundary".into(),
                                                ResolutionIncompleteReason::Cancelled => "cancelled".into(),
                                                ResolutionIncompleteReason::CyclicExpansion(_) => "cyclic_expansion".into(),
                                                ResolutionIncompleteReason::CyclicPrefixDependency(_) => "cyclic_prefix_dependency".into(),
                                                ResolutionIncompleteReason::InconsistentPrecedence(_) => "inconsistent_precedence".into(),
                                                ResolutionIncompleteReason::ReceiverBudgetExhausted(_) => "receiver_budget_exhausted".into(),
                                                ResolutionIncompleteReason::TimeBudgetExceeded(_) => "time_budget_exceeded".into(),
                                                ResolutionIncompleteReason::UnmountedFile {..} => "unmounted_file".into(),
                                            };
                                            obligations.push(label);
                                        }
                                    }
                                    if label_open {
                                        receiver_relation = Some(reverse::ReverseTargetRelation::Undecided);
                                        obligations.push("python_named_argument_open".into());
                                    } else if field_identity.is_some() || external_receiver_excluded { obligations.clear(); }
                                    reverse::ReverseBatch::Ready(vec![PythonReverseAnswer {answer,field_identity,label_open,obligations,receiver_relation}])
                                }
                                FactDemandResolution::Cancelled(completion) => {
                                    reverse::ReverseBatch::Cancelled {
                                        stage: reverse::ReverseCancellationStage::Projection,
                                        completion,
                                    }
                                }
                            },
                        )
                    },
                })
            },
        )
    }
}

/// Required environment authority for one admitted caller, independent of hits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PythonReverseContext {
    summary: i64,
    profile: super::python_lexical::PythonBindingProfile,
    unit: Vec<u8>,
}

/// Query-local native answers; production Python find-usages stays on its
/// existing strategy until publication and cost admission are approved.
pub struct PythonNativeReverseResult {
    /// All scoped nomination files, including excluded and unconfirmed sites.
    pub nominated_paths: Vec<String>,
    /// Openness outside the selected environment, reported once per query.
    pub query_obligations: Vec<String>,
    pub targets: Vec<PythonNativeReverseTarget>,
    pub unavailable: Vec<PythonNativeReverseUnavailableTarget>,
    /// Targets not attempted because a preceding target stopped the batch.
    pub unprocessed: Vec<PythonNativeReverseUnavailableTarget>,
    inventory: String,
}
pub struct PythonNativeReverseUnavailableTarget {
    pub target: CodeUnit,
    pub reason: String,
}
pub struct PythonNativeReverseTarget {
    pub target: CodeUnit,
    // The ledger keys this unit request by its first authored identity. The
    // classifier retains and tests the complete authored group alongside it.
    semantic: SemanticId,
    semantics: Vec<SemanticId>,
    field_slot: Option<PythonModuleField>,
    pub authored_definitions: usize,
    pub sites: Vec<PythonNativeReverseSite>,
    pub complete: bool,
    pub obligations: Vec<String>,
    pub confirmation_sql: Option<(u64, u64)>,
    pub confirmation_elapsed: std::time::Duration,
    receipt: String,
    proof: reverse::ReverseProofBatch<PythonReverseContext>,
}
#[derive(Debug)]
pub struct PythonNativeReverseSite {
    pub path: String,
    pub start: usize,
    pub end: usize,
    pub certain: bool,
    pub potential: bool,
    /// A point-answer relation requiring complete binding and applicability.
    /// Route and target obligations remain in the target's completeness.
    /// Environment-wide openness is retained once on the query result. This
    /// is not a certain negative for consumers outside the selected environment.
    pub excluded: bool,
    /// A site with no reports is undecided with python_reverse_locator_missing,
    /// never excluded.
    pub undecided: bool,
    /// Forward origins from answers matching this target, independent of owner relation.
    pub receiver_origins: Vec<ResolutionCallableReceiverOrigin>,
    pub obligations: Vec<String>,
}
impl PythonNativeReverseResult {
    #[cfg(any(test, feature = "test-support"))]
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut output = self.inventory.clone();
        writeln!(output, "query-obligations={:?}", self.query_obligations).expect("String write");
        for target in &self.targets {
            output.push_str(&target.receipt);
            writeln!(output, "context-obligations={:?}", target.obligations).expect("String write");
            for label in ["certain", "potential", "excluded", "undecided"] {
                let sites = target
                    .sites
                    .iter()
                    .filter(|site| match label {
                        "certain" => site.certain,
                        "potential" => site.potential,
                        "excluded" => site.excluded,
                        _ => site.undecided,
                    })
                    .map(|site| format!("{}:{}..{}", site.path, site.start, site.end))
                    .collect::<Vec<_>>();
                writeln!(output, "{label}={sites:?}").expect("String write");
            }
            for site in &target.sites {
                writeln!(
                    output,
                    "  {}:{}..{} obligations={:?}",
                    site.path, site.start, site.end, site.obligations
                )
                .expect("String write");
            }
            writeln!(
                output,
                "confirmation complete={} contexts={}",
                target.complete,
                target.proof.required.len()
            )
            .expect("String write");
        }
        for unavailable in &self.unavailable {
            writeln!(
                output,
                "target {} unavailable={}",
                unavailable.target.fq_name_str(),
                unavailable.reason
            )
            .expect("String write");
        }
        for unprocessed in &self.unprocessed {
            writeln!(
                output,
                "target {} unprocessed={}",
                unprocessed.target.fq_name_str(),
                unprocessed.reason
            )
            .expect("String write");
        }
        output
    }
}

// Ordinary references and operation-only names have distinct retained
// position domains. Member sites do not inventory ordinary references.
fn python_site_range(conn: &rusqlite::Connection, blob: i64, site: u32) -> Result<(usize, usize)> {
    Ok(conn
        .prepare_cached(
            "SELECT start_byte,end_byte FROM resolution_sites
             WHERE blob_id=?1 AND site=?2 AND role=0 AND start_byte IS NOT NULL
             UNION
             SELECT start_byte,end_byte FROM python_member_sites WHERE blob_id=?1 AND site=?2",
        )?
        .query_row(params![blob, site], |row| Ok((row.get(0)?, row.get(1)?)))?)
}

struct PythonReverseFiles<'a, 'store, 'input> {
    constructions: &'a construction::ConstructionFamily,
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    view: &'a PythonReverseView,
    python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    cancellation: &'a CancellationToken,
    target: &'a mut PythonNativeReverseTarget,
    session: Option<&'a ResolutionSession>,
    retained: &'a Cell<usize>,
    truncated: &'a Cell<bool>,
    max_sites: usize,
    receivers: &'a HashMap<SelectedSemanticLocator, PythonReverseReceiver>,
}
impl PythonReverseFiles<'_, '_, '_> {
    fn retain_site(&mut self, site: PythonNativeReverseSite) {
        if !site.excluded {
            if self.retained.get() >= self.max_sites {
                self.truncated.set(true);
                return;
            }
            self.retained.set(self.retained.get() + 1);
        }
        self.target.sites.push(site);
    }

    fn site(&self, locator: &SelectedSemanticLocator) -> Result<PythonNativeReverseSite> {
        let mount = self
            .operation
            .mount_table()
            .mount_for_path("python", locator.relative_path())?
            .expect("selected Python caller");
        // Ordinary references and operation-only names have distinct retained
        // position domains. Member sites do not inventory ordinary references.
        // Dynamic namespace usage is displayed on the receiver, as in the
        // ordinary module-reference path. Keep the operation locator for proof.
        let source_site = if let Some(receiver) = self.receivers.get(locator) {
            self.operation
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT source_site FROM resolution_semantic_sites
                 WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'",
                )?
                .query_row(
                    params![
                        self.operation
                            .ready
                            .inventory
                            .mount_record_by_ordinal(mount.ordinal())?
                            .blob_id(),
                        receiver
                            .reference
                            .local_key()
                            .expect("mounted receiver reference"),
                    ],
                    |row| row.get(0),
                )?
        } else {
            locator
                .source_site()
                .expect("Python source nomination")
                .get()
        };
        let (start, end) = python_site_range(
            self.operation.ready.inventory.connection(),
            self.operation
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?
                .blob_id(),
            source_site,
        )?;
        Ok(PythonNativeReverseSite {
            path: locator.relative_path().into(),
            start,
            end,
            certain: false,
            potential: false,
            excluded: false,
            undecided: true,
            receiver_origins: Vec::new(),
            obligations: Vec::new(),
        })
    }
    fn retain(
        &mut self,
        locators: &[SelectedSemanticLocator],
        batch: reverse::ReverseContextBatch<
            reverse::ReverseContextId<PythonReverseContext>,
            PythonReverseAnswer,
        >,
    ) -> Result<()> {
        let required = self.target.proof.extend_contexts(batch.required);
        let module_sites = std::cell::RefCell::new(
            crate::analyzer::store::selected_read_memo::RequestReadCache::default(),
        );
        for (locator, mut site) in locators.iter().zip(batch.sites) {
            for (context, _) in &mut site.reports {
                *context = required[*context];
            }
            let mut rendered = self.site(locator)?;
            if site.reports.is_empty() {
                let label = format!("{}:{}..{}", rendered.path, rendered.start, rendered.end);
                let mut hash = CanonicalHasher::new(b"python-reverse-missing-locator:v1");
                hash.field("site", label.as_bytes());
                let reason = self.operation.ready.context_identities.named_semantic(
                    hash.finish(),
                    "python_reverse_locator_missing",
                    &label,
                );
                for &context in &required {
                    let handle = self.target.proof.evidence.binding.record(
                        reverse::ReverseSubject::Site(
                            locator.clone(),
                            self.target.proof.required[context].selected.clone(),
                        ),
                        reverse::ReverseEvidenceOrigin::Binding,
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(reason),
                        ]),
                    );
                    assert!(
                        self.target
                            .proof
                            .obligation_contexts
                            .insert(handle, context)
                            .is_none()
                    );
                }
                rendered
                    .obligations
                    .push("python_reverse_locator_missing".into());
            }
            let unknown_name: bool = self.operation.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM temp.python_reverse_operations op JOIN temp.selected_resolution_mounts mounts ON mounts.mount_ordinal=op.mount WHERE mounts.persisted_relative_path=?1 AND op.name_site=?2 AND op.name_kind<>0)")?.query_row(
                params![locator.relative_path(),locator.source_site().expect("Python source nomination").get()], |row| row.get(0))?;
            let name_completion = if unknown_name {
                let label = format!("{}:{}..{}", rendered.path, rendered.start, rendered.end);
                let mut hash = CanonicalHasher::new(b"python-reverse-unknown-member-name:v1");
                hash.field("site", label.as_bytes());
                let reason = self.operation.ready.context_identities.named_semantic(
                    hash.finish(),
                    "python_unknown_member_name",
                    &label,
                );
                rendered
                    .obligations
                    .push("python_unknown_member_name".into());
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    reason,
                )])
            } else {
                ResolutionCompletion::Complete
            };
            let targets = &self.target.semantics;
            // A complete binding that selects the target among several
            // alternatives (a local rebound to two classes on different
            // branches, a function defined twice) may reach any of them, so it
            // matches without closing identity. As in the shared
            // `current_target_usage_proof`, only a unique selection is
            // certain. A binding that excludes the target still closes the
            // site as excluded.
            //
            // A module paired with one declaration of its own file is not a
            // pair of alternatives. A from-import of a package attribute that
            // the package's `from .x import x` rebinds unions the attribute
            // with the child module `x` (python_demand route_tier), and both
            // name the one exported value.
            let mut competing = HashSet::default();
            for (_, answers) in &site.reports {
                for answer in answers {
                    let selected = answer.answer.answer.binding().targets();
                    if !matches!(selected, [_, _, ..])
                        || !selected.iter().any(|target| targets.contains(target))
                    {
                        continue;
                    }
                    let module_and_member = match selected {
                        &[first, second] if first.ordinal() == second.ordinal() => {
                            super::python_demand::is_module_definition(
                                &self.operation.ready.inventory,
                                first,
                                &module_sites,
                            )? != super::python_demand::is_module_definition(
                                &self.operation.ready.inventory,
                                second,
                                &module_sites,
                            )?
                        }
                        _ => false,
                    };
                    if !module_and_member {
                        competing.insert(selected);
                    }
                }
            }
            let closes_identity = |selected: &[SemanticId]| !competing.contains(selected);
            // Identity closure is independent of call/type applicability in
            // Python. Require a report from every selected file context.
            let identity_closed = !required.is_empty()
                && required.iter().all(|context| {
                    site.reports.iter().any(|(reported, answers)| {
                        reported == context
                            && !answers.is_empty()
                            && answers.iter().all(|answer| {
                                matches!(
                                    answer.answer.receiver_relation,
                                    Some(reverse::ReverseTargetRelation::Excluded)
                                ) || (!unknown_name
                                    && !answer.answer.label_open
                                    && (answer.answer.field_identity.is_some()
                                        || (answer.answer.answer.binding().completion()
                                            == &ResolutionCompletion::Complete
                                            && closes_identity(
                                                answer.answer.answer.binding().targets(),
                                            ))))
                            })
                    })
                });
            let open_completion = if site
                .reports
                .iter()
                .any(|(_, answers)| answers.iter().any(|answer| answer.answer.label_open))
            {
                let mut hash = CanonicalHasher::new(b"python-reverse-named-argument-open:v1");
                hash.field("path", locator.relative_path().as_bytes());
                hash.field(
                    "site",
                    &locator
                        .source_site()
                        .expect("Python source nomination")
                        .get()
                        .to_le_bytes(),
                );
                let open_reason = self.operation.ready.context_identities.named_semantic(
                    hash.finish(),
                    "python_named_argument_open",
                    locator.relative_path(),
                );
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    open_reason,
                )])
            } else {
                ResolutionCompletion::Complete
            };
            let mut inventory_obligations = Vec::new();
            let reduction = reverse::classify_reverse_context_site(
                &mut self.target.proof,
                locator,
                &required,
                site,
                |answer: PythonReverseAnswer| {
                    let receiver_excluded = matches!(
                        answer.receiver_relation,
                        Some(reverse::ReverseTargetRelation::Excluded)
                    );
                    let binding = if answer.label_open {
                        open_completion.clone()
                    } else if answer.field_identity.is_some()
                        || answer.receiver_relation.is_some_and(|relation| {
                            !matches!(relation, reverse::ReverseTargetRelation::Undecided)
                        })
                    {
                        ResolutionCompletion::Complete
                    } else {
                        answer.answer.binding().completion().clone()
                    };
                    let applicability = if answer.label_open {
                        open_completion.clone()
                    } else if receiver_excluded {
                        ResolutionCompletion::Complete
                    } else if answer.field_identity.is_some() {
                        name_completion.clone()
                    } else {
                        answer
                            .answer
                            .call_target_completion()
                            .combine(&name_completion)
                    };
                    for (facet, completion) in
                        [("binding", &binding), ("enumeration", &applicability)]
                    {
                        if *completion != ResolutionCompletion::Complete {
                            inventory_obligations.push(format!(
                                "python_reverse_{facet}_incomplete:{}:{}..{}:{:?}",
                                rendered.path, rendered.start, rendered.end, answer.obligations,
                            ));
                        }
                    }
                    let closes_site = receiver_excluded
                        || (!unknown_name
                            && binding == ResolutionCompletion::Complete
                            && applicability == ResolutionCompletion::Complete);
                    let matches = answer.field_identity.unwrap_or_else(|| {
                        targets
                            .iter()
                            .any(|target| answer.answer.binding().targets().contains(target))
                    });
                    let relation = if answer.field_identity == Some(true) {
                        reverse::ReverseTargetRelation::Matches
                    } else if answer.field_identity == Some(false) {
                        reverse::ReverseTargetRelation::Excluded
                    } else if let Some(relation) = answer.receiver_relation {
                        relation
                    } else if matches {
                        reverse::ReverseTargetRelation::Matches
                    } else if closes_site {
                        reverse::ReverseTargetRelation::Excluded
                    } else {
                        reverse::ReverseTargetRelation::Undecided
                    };
                    Ok(Some(reverse::ReverseClassifiedView {
                        verdict: reverse::ReverseViewVerdict {
                            relation,
                            closes_site,
                            closure: (),
                            answer,
                        },
                        applicability,
                        binding,
                    }))
                },
            )?
            .expect("Python classifier always reports");
            // Site closure comes from every independently selected forward
            // report. Environment enumeration obligations remain on the query
            // ledger; a certain local binding does not discharge them.
            rendered.certain = !reduction.binding.is_empty() && identity_closed;
            rendered.potential = !reduction.binding.is_empty() && !rendered.certain;
            rendered.excluded = reduction.binding.is_empty()
                && reduction.undecided.is_empty()
                && reduction.every_context_closed;
            debug_assert!(!rendered.excluded || identity_closed);
            rendered.undecided = !reduction.undecided.is_empty()
                || (!rendered.excluded && reduction.binding.is_empty());
            for origin in reduction
                .binding
                .iter()
                .filter_map(|answer| answer.answer.site_metadata()?.receiver_origin())
            {
                if !rendered.receiver_origins.contains(&origin) {
                    rendered.receiver_origins.push(origin);
                }
            }
            for answer in reduction
                .binding
                .iter()
                .chain(&reduction.rejecting)
                .chain(&reduction.undecided)
            {
                rendered
                    .obligations
                    .extend(answer.obligations.iter().cloned());
            }
            // Environment obligations are independent of point answers, even
            // when a reference binds or is completely disjoint from this target.
            rendered.obligations.extend(
                self.view
                    .obligations
                    .iter()
                    .filter(|obligation| obligation.affects(locator.relative_path()))
                    .map(|obligation| obligation.label.clone()),
            );
            rendered.obligations.sort();
            rendered.obligations.dedup();
            self.target.obligations.extend(inventory_obligations);
            if !rendered.obligations.is_empty() {
                self.target.obligations.push(format!(
                    "python_reverse_site_obligations:{}:{}..{}:{:?}",
                    rendered.path, rendered.start, rendered.end, rendered.obligations,
                ));
            }
            self.retain_site(rendered);
        }
        Ok(())
    }
}
impl reverse::ReverseFileHooks<Vec<SelectedSemanticLocator>> for PythonReverseFiles<'_, '_, '_> {
    type Session = reverse::ReverseContextBatch<
        reverse::ReverseContextId<PythonReverseContext>,
        PythonReverseAnswer,
    >;
    type Limit = brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
    fn confirm(
        &mut self,
        file: &mut reverse::ReverseFile<Vec<SelectedSemanticLocator>>,
    ) -> Result<reverse::ReverseBatch<Self::Session, Self::Limit>> {
        self.view
            .validate_current_use(self.operation, self.cancellation)?;
        let mount = self
            .operation
            .mount_table()
            .mount_for_path("python", file.payload[0].relative_path())?
            .expect("selected Python caller");
        let blob = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?
            .blob_id();
        let context = reverse::ReverseContextId {
            selected: ReverseContextWitness::new(self.operation, mount.ordinal().get(), blob),
            view: self.view.context.clone(),
        };
        let locators = file.payload.iter().collect::<Vec<_>>();
        reverse::confirm_reverse_contexts(vec![context], &locators, self.cancellation, |_| {
            let run = |session: &ResolutionSession, cancellation: &CancellationToken| {
                reverse::confirm_reverse_session(
                    &locators,
                    &mut PythonReverseLifecycle {
                        constructions: self.constructions,
                        operation: self.operation,
                        summary: self.view.summary,
                        python_version: self.python_version,
                        cancellation,
                        session,
                        field_slot: self.target.field_slot.as_ref(),
                        targets: &self.target.semantics,
                        target_is_field: self.target.target.is_field(),
                        target_name: self.target.target.identifier(),
                        profile: self.view.context.profile,
                        receivers: self.receivers,
                    },
                )
            };
            let bounded = match self.session {
                Some(session) => session.finish(run(session, self.cancellation)?),
                None => confirm_reverse_session_bounded(
                    locators.len(),
                    ReceiverAnalysisBudget::default(),
                    self.cancellation,
                    run,
                )?,
            };
            Ok(match bounded {
                BoundedResolution::Complete { value, .. } => {
                    value.map_limit(|never| match never {})
                }
                BoundedResolution::Exceeded { limit, .. } => reverse::ReverseBatch::Bounded(limit),
                BoundedResolution::Unavailable { reason, .. } => {
                    reverse::ReverseBatch::Unavailable(
                        SelectedResolutionUnavailable::CatalogInputUnavailable { reason },
                    )
                }
                BoundedResolution::Cancelled { .. } => reverse::ReverseBatch::Cancelled {
                    stage: reverse::ReverseCancellationStage::Context,
                    completion: cancelled_completion(),
                },
            })
        })
    }
    fn commit(
        &mut self,
        file: reverse::ReverseFile<Vec<SelectedSemanticLocator>>,
        session: Self::Session,
    ) -> Result<reverse::ReverseBlobControl> {
        self.retain(&file.payload, session)?;
        Ok(reverse::ReverseBlobControl::Continue)
    }
    fn stopped(
        &mut self,
        file: reverse::ReverseFile<Vec<SelectedSemanticLocator>>,
        outcome: reverse::ReverseBatch<std::convert::Infallible, Self::Limit>,
    ) -> Result<reverse::ReverseBlobControl> {
        let (control, completion, label) = match outcome {
            reverse::ReverseBatch::Ready(never) => match never {},
            reverse::ReverseBatch::Bounded(limit) => {
                let label = limit.as_str();
                self.target
                    .obligations
                    .push(format!("python_reverse_resolution_budget_exceeded:{label}"));
                let mut hash = CanonicalHasher::new(b"python-resolution-budget:v1");
                hash.field("limit", label.as_bytes());
                let reason = self.operation.ready.context_identities.named_semantic(
                    hash.finish(),
                    "python_resolution_budget_exceeded",
                    label,
                );
                (
                    reverse::ReverseBlobControl::Continue,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ]),
                    label,
                )
            }
            reverse::ReverseBatch::TimeStopped => (
                reverse::ReverseBlobControl::TimeBudgetExceeded,
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::TimeBudgetExceeded(
                    self.target.semantic,
                )]),
                "time_stopped",
            ),
            reverse::ReverseBatch::Cancelled { completion, .. } => (
                reverse::ReverseBlobControl::Cancelled,
                completion,
                "cancelled",
            ),
            reverse::ReverseBatch::Stale(reason) => {
                return Err(StoreError::new(format!(
                    "stale Python reverse context: {reason:?}"
                )));
            }
            reverse::ReverseBatch::Unavailable(reason) => {
                return Err(StoreError::new(format!(
                    "unavailable Python reverse context: {reason:?}"
                )));
            }
            reverse::ReverseBatch::UnsupportedContext => {
                return Err(StoreError::new("unsupported Python reverse context"));
            }
        };
        self.target.complete = false;
        self.target
            .obligations
            .push(format!("python_reverse_{label}"));
        for locator in &file.payload {
            let mut site = self.site(locator)?;
            site.obligations.push(label.into());
            let mount = self
                .operation
                .mount_table()
                .mount_for_path("python", locator.relative_path())?
                .expect("selected stopped caller");
            let selected = ReverseContextWitness::new(
                self.operation,
                mount.ordinal().get(),
                self.operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())?
                    .blob_id(),
            );
            let context = self
                .target
                .proof
                .extend_contexts(vec![reverse::ReverseContextId {
                    selected: selected.clone(),
                    view: self.view.context.clone(),
                }])[0];
            let handle = self.target.proof.evidence.binding.record(
                reverse::ReverseSubject::Site(locator.clone(), selected),
                reverse::ReverseEvidenceOrigin::Binding,
                completion.clone(),
            );
            assert!(
                self.target
                    .proof
                    .obligation_contexts
                    .insert(handle.clone(), context)
                    .is_none()
            );
            self.target.proof.sites.push(reverse::ReverseSiteEvidence {
                target: self.target.semantic,
                input_ordinal: 0,
                locator: locator.clone(),
                context,
                domain: vec![context],
                obligations: vec![handle],
                meanings: Vec::new(),
            });
            self.retain_site(site);
        }
        Ok(control)
    }
}
