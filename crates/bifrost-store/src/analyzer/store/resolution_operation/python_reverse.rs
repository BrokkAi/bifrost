//! Python exposure rules for the shared reverse nomination worklist. This
//! dormant entry confirms nominations without changing production usages.
use super::super::python_unit_summaries::PythonSelectedEnvironment;
use super::reverse_candidates::{
    REVERSE_LOOKUP_IDENTITY_ARM_SQL, ReverseCandidateKey, ReverseContextWitness,
};
use super::reverse_nomination::{
    ReverseExposure, ReverseExposureSeeds, ReverseExposureStep, ReverseLookupSource,
    ReverseNominationHooks, ReverseSourceLookup, nominate_reverse_target,
};
use super::*;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use rusqlite::{OptionalExtension, params};
use std::cell::Cell;

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
/// A getattr/setattr/delattr/patch with a wholly unknown member name can reference
/// the target without being listed, as with JVM and Go reflection today. Known
/// prefixes still nominate matching targets as undecided candidates. If computed-name
/// access with a resolved module or class receiver proves common, nominate it for
/// that receiver's members only. Constant names lost by the producer are #7182.
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
}
impl PythonReverseView {
    fn select(
        operation: &SelectedResolutionOperation<'_, '_>,
        summary: i64,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let conn = operation.ready.inventory.connection();
        let (mut unit, digest, output, complete): (Vec<u8>,String,String,bool) = conn.query_row(
            "SELECT unit_key,hex(summary_digest),hex(output_digest),complete FROM resolution_unit_summaries WHERE summary_id=?1 AND lang='python' AND publication_state='complete'", [summary],
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
        let profile = conn.query_row(
            "SELECT observation FROM python_unit_summary_roots WHERE summary_id=?1 LIMIT 1",
            [summary],
            |row| row.get::<_, String>(0),
        )?;
        let raw_unit = conn.query_row(
            "SELECT unit_key FROM resolution_unit_summaries WHERE summary_id=?1",
            [summary],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let gaps = conn.prepare_cached("SELECT gap_kind,subject,json(detail) FROM resolution_unit_summary_gaps WHERE summary_id=?1 ORDER BY gap_kind,subject")?
            .query_map([summary], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut obligations = Vec::new();
        let mut unplaced = Vec::new();
        let mutation_profile = match profile.as_str() {
            "runtime" => super::python_lexical::PythonBindingProfile::Runtime,
            "typing" => super::python_lexical::PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python reverse profile")),
        };
        let mutations = super::python_members::operations::structural_mutations(
            &operation.ready,
            summary,
            mutation_profile,
            &ResolutionSession::unbounded(),
            cancellation,
        )?;
        let mut query_obligations =
            super::python_demand::selected_environment_obligations(&operation.ready, summary)?;
        if let Some(obligation) =
            super::python_members::operations::dynamic_receiver_query_obligation(&mutations)
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
        for row in conn.prepare_cached("SELECT members.rel_path,imports.import_site,imports.state FROM python_unit_summary_imports imports JOIN resolution_unit_summary_members members ON members.summary_id=imports.summary_id AND members.member_ordinal=imports.member_ordinal WHERE imports.summary_id=?1 AND imports.state='activation_open' ORDER BY members.rel_path,imports.import_site")?
            .query_map([summary], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,String>(2)?)))? {
            let (caller, site, state) = row?;
            let label = format!("python_import_activation_open:{caller}:site={site}:{state}");
            let mut hash = CanonicalHasher::new(b"python-reverse-import-obligation:v1");
            hash.field("unit", &raw_unit); hash.field("profile", profile.as_bytes()); hash.field("import",label.as_bytes());
            let reason = operation.ready.context_identities.named_semantic(hash.finish(),"python_import_activation_open",&label);
            obligations.push(PythonReverseObligation {completion:ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)]),label,caller:Some(caller),coverage:PythonReverseCoverage::Enumeration});
        }
        for row in conn.prepare_cached("SELECT DISTINCT members.rel_path,imports.import_site,imports.state FROM python_unit_summary_imports imports JOIN resolution_unit_summary_members members ON members.summary_id=imports.summary_id AND members.member_ordinal=imports.member_ordinal WHERE imports.summary_id=?1 AND imports.state IN ('relative_context_open','provider_open') ORDER BY members.rel_path,imports.import_site")?
            .query_map([summary], |row| Ok((row.get::<_,String>(0)?,row.get::<_,u32>(1)?,row.get::<_,String>(2)?)))? {
            let (caller, site, state) = row?;
            let (completion, label) = super::python_demand::import_route_obligation(&operation.ready, summary, &caller, site, &state)?;
            obligations.push(PythonReverseObligation { completion, label, caller:Some(caller), coverage:PythonReverseCoverage::CandidatesAndEnumeration });
        }
        Ok(Self {
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
        })
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
            let (blob, site) = self.conn().query_row(
                super::reverse_nomination::REVERSE_DEFINITION_SITE_SQL,
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
        // Only from-imports rename a member; module imports bind its container.
        for row in self.conn().prepare_cached("SELECT imports.importer_container,imports.bound_name,imports.form,imports.import_site,member.blob_id,coalesce(binding_slot.scope,root.root_scope),policy.policy,EXISTS(SELECT 1 FROM python_unit_summary_export_names names WHERE names.summary_id=imports.summary_id AND names.container_path=imports.target_container AND names.surface='wildcard' AND names.name=?3) FROM python_unit_summary_imports imports INDEXED BY python_unit_summary_imports_reverse JOIN resolution_unit_summary_members member ON member.summary_id=imports.summary_id AND member.member_ordinal=imports.member_ordinal JOIN python_unit_summary_providers importer ON importer.summary_id=imports.summary_id AND importer.container_path=imports.importer_container AND importer.state<>'shadowed' JOIN resolution_root_imports root ON root.blob_id=member.blob_id AND root.import_site=imports.import_site LEFT JOIN python_binding_imports source_import ON source_import.blob_id=member.blob_id AND source_import.import_site=imports.import_site LEFT JOIN resolution_binding_events binding_event ON binding_event.blob_id=member.blob_id AND binding_event.event=source_import.binding_event LEFT JOIN resolution_binding_slots binding_slot ON binding_slot.blob_id=member.blob_id AND binding_slot.slot=binding_event.slot LEFT JOIN python_unit_summary_surfaces policy ON policy.summary_id=imports.summary_id AND policy.container_path=imports.target_container AND policy.surface='wildcard' WHERE imports.summary_id=?1 AND imports.target_container=?2 AND ((imports.form='from' AND imports.requested_name=?3) OR imports.form='star' OR (?4 AND imports.form='module')) ORDER BY imports.member_ordinal,imports.import_site,imports.importer_container")?.query_map(params![self.view.summary,exposure.module,exposure.name,self.target.is_module()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,u32>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,bool>(7)?)))? {
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
        // A module qualifier is not an alias of a contained declaration.
        // Qualified member uses are nominated by their terminal spelling.
        if !self.target.is_module() {
            return Ok(step);
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
        // The synthetic callee-value read retains qualifier, service and context
        // reasons the call reference may lack. It is an operation-internal fact,
        // not a user-addressable reference. Both reverse consumers select here.
        let observed: bool = self.conn().query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM python_member_operations WHERE blob_id=?1 AND callee_reference=?2)
             AND (EXISTS(SELECT 1 FROM python_member_operations WHERE blob_id=?1 AND name_site=?2) OR (EXISTS(SELECT 1 FROM resolution_binding_observations WHERE blob_id=?1 AND reference=?2)
                AND NOT EXISTS(SELECT 1 FROM resolution_binding_slots WHERE blob_id=?1 AND slot=?2)
                AND NOT EXISTS(
                    SELECT 1 FROM resolution_binding_events events INDEXED BY resolution_binding_events_target
                    JOIN temp.python_reverse_evidence seed ON seed.kind='seed'
                      AND seed.blob=events.blob_id AND seed.site=events.authored
                    WHERE events.blob_id=?1 AND events.target=?2)))",
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
        let mut labels = view.query_obligations;
        for obligation in view.obligations {
            labels.push(obligation.label);
        }
        Ok((labels, view.unplaced))
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
        let view = PythonReverseView::select(self, summary, cancel)?;
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
            let cleared = conn.execute("DELETE FROM temp.python_reverse_evidence", [])?;
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
                sites: Vec::new(),
                complete: true,
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
                let operation: Option<(u32,u32)> = conn.query_row("SELECT op.name_kind,op.possible_replacement FROM temp.python_reverse_operations op WHERE op.mount=?1 AND op.name_site=?2", params![mount.ordinal().get(),locator.source_site().expect("Python source nomination").get()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
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
            answer.complete &= !answer.proof.required.is_empty()
                && answer
                    .proof
                    .evidence
                    .enumeration
                    .completion_with_poll(&mut || cancel.is_cancelled())
                    == Some(ResolutionCompletion::Complete)
                && answer
                    .proof
                    .evidence
                    .binding
                    .completion_with_poll(&mut || cancel.is_cancelled())
                    == Some(ResolutionCompletion::Complete)
                && answer
                    .proof
                    .evidence
                    .metadata
                    .completion_with_poll(&mut || cancel.is_cancelled())
                    == Some(ResolutionCompletion::Complete);
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
        Ok(result)
    }
}

struct PythonReverseAnswer {
    answer: FactResolutionAnswer,
    obligations: Vec<String>,
}

// The shared lifecycle owns ordering; these hooks supply the selected Python
// environment and one bounded forward operation per caller slice.
struct PythonReverseLifecycle<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    summary: i64,
    python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    cancellation: &'a CancellationToken,
    session: &'a ResolutionSession,
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
            operation: self.operation,
            summary: self.summary,
            python_version: self.python_version,
            cancellation: self.cancellation,
            session: self.session,
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
            |operation, provider, _, _, _| {
                run(&mut reverse::ReverseEvaluatorFn {
                    marker: std::marker::PhantomData,
                    run: |_: &SelectedSemanticLocator, semantic: SemanticId| {
                        if !self.session.scope_step() || self.cancellation.is_cancelled() {
                            // ResolutionSession::finish owns the stop classification:
                            // scope-step exhaustion becomes Exceeded from the session's
                            // stop state, even though this stage reports Cancelled.
                            return Ok(reverse::ReverseBatch::Cancelled {
                                stage: reverse::ReverseCancellationStage::Projection,
                                completion: cancelled_completion(),
                            });
                        }
                        Ok(
                            match operation.resolve_reference_by_demand(semantic, provider)? {
                                FactDemandResolution::Ready(answer) => {
                                    let completion = answer.binding().completion().combine(answer.completion());
                                    let mut obligations = named_reason_details(&self.operation.ready,&completion)?.into_iter().map(|(kind,detail)|format!("{kind}:{detail}")).collect::<Vec<_>>();
                                    if let ResolutionCompletion::Incomplete(reasons) = &completion {
                                        for reason in reasons.iter() {
                                            let label = match reason {
                                                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => operation.service_reason_details(*semantic).map(|(name,_)| name.to_owned()).unwrap_or_else(|| "unsupported_semantic".into()),
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
                                    reverse::ReverseBatch::Ready(vec![PythonReverseAnswer {answer:*answer,obligations}])
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
    pub obligations: Vec<String>,
}
impl PythonNativeReverseResult {
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

struct PythonReverseFiles<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    view: &'a PythonReverseView,
    python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    cancellation: &'a CancellationToken,
    target: &'a mut PythonNativeReverseTarget,
    session: Option<&'a ResolutionSession>,
    retained: &'a Cell<usize>,
    truncated: &'a Cell<bool>,
    max_sites: usize,
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
        let (start, end) = self.operation.ready.inventory.connection().query_row(
            "SELECT start_byte,end_byte FROM resolution_sites
             WHERE blob_id=?1 AND site=?2 AND role=0 AND start_byte IS NOT NULL
             UNION
             SELECT start_byte,end_byte FROM python_member_sites WHERE blob_id=?1 AND site=?2",
            params![
                self.operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())?
                    .blob_id(),
                locator
                    .source_site()
                    .expect("Python source nomination")
                    .get()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(PythonNativeReverseSite {
            path: locator.relative_path().into(),
            start,
            end,
            certain: false,
            potential: false,
            excluded: false,
            undecided: true,
            obligations: Vec::new(),
        })
    }
    fn is_import_binding(&self, site: &PythonNativeReverseSite) -> Result<bool> {
        let is_import_binding: bool = self.operation.ready.inventory.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts mount
             JOIN source_imports imports ON imports.blob_id=mount.blob_id
             WHERE mount.storage_language='python' AND mount.persisted_relative_path=?1
               AND imports.declaration_start_byte<=?2 AND imports.declaration_end_byte>=?3)",
            params![site.path, site.start, site.end],
            |row| row.get(0),
        )?;
        Ok(is_import_binding)
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
            let unknown_name: bool = self.operation.ready.inventory.connection().query_row(
                "SELECT EXISTS(SELECT 1 FROM temp.python_reverse_operations op JOIN temp.selected_resolution_mounts mounts ON mounts.mount_ordinal=op.mount WHERE mounts.persisted_relative_path=?1 AND op.name_site=?2 AND op.name_kind<>0)",
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
            // Identity closure is independent of call/type applicability in
            // Python. Require a report from every selected file context.
            let identity_closed = !unknown_name
                && !required.is_empty()
                && required.iter().all(|context| {
                    site.reports.iter().any(|(reported, answers)| {
                        reported == context
                            && !answers.is_empty()
                            && answers.iter().all(|answer| {
                                answer.answer.answer.binding().completion()
                                    == &ResolutionCompletion::Complete
                            })
                    })
                });
            let targets = &self.target.semantics;
            let reduction = reverse::classify_reverse_context_site(
                &mut self.target.proof,
                locator,
                &required,
                site,
                |answer: PythonReverseAnswer| {
                    let binding = answer.answer.binding().completion().clone();
                    let applicability = answer.answer.completion().combine(&name_completion);
                    let closes_site = !unknown_name
                        && binding == ResolutionCompletion::Complete
                        && applicability == ResolutionCompletion::Complete;
                    let relation = if targets
                        .iter()
                        .any(|target| answer.answer.binding().targets().contains(target))
                    {
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
            if !self.is_import_binding(&rendered)? {
                self.retain_site(rendered);
            }
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
                        operation: self.operation,
                        summary: self.view.summary,
                        python_version: self.python_version,
                        cancellation,
                        session,
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
            if !self.is_import_binding(&site)? {
                self.retain_site(site);
            }
        }
        Ok(control)
    }
}
