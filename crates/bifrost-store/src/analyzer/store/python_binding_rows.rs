//! Retained source inputs for one selected Python blob. All returned collections
//! are read through the store budget; no module or workspace index is retained.
use super::{AnalyzerStore, WorkspaceSnapshotId};
use super::{Result, StoreError};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::resolution_facts::*;
#[cfg(any(test, feature = "test-support"))]
use rusqlite::OptionalExtension;
use rusqlite::{Connection, Transaction, params};

/// Construct the Python-owned, operation-local module declaration classifier.
#[cfg(any(test, feature = "test-support"))]
pub fn namespace_definition_provider()
-> Box<dyn super::language_support::NamespaceDefinitionClassifier> {
    super::resolution_operation::python_demand::namespace_definition_provider()
}

// Format 2 added typed slots and authored member kinds. Format 3 also requires
// lexical root references, preventing cached reads from bypassing temporal closure.
// Format 5 adds direct alias observations and positioned lookup requests.
// Format 6 also requires member role/base inputs and compiler proxy contexts.
// Format 7 fixes authored parameter/field type owners and positional receiver roles.
// Format 7 also publishes direct assignment Value properties for typed reads.
// Production builds do not admit Python to selected overlays. Test-support builds
// admit it for the native trial; their test-support stores are rejected by the
// flip's format bump. The production flip ends this freeze and sets the format
// once with its rejection test (#6108).
pub(crate) const NATIVE_SOURCE_FORMAT: i64 = 7;
// Dormant inputs also retain dynamic operations and exact/prefix/Any names.

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct BindingScope {
    pub(crate) scope: u32,
    pub(crate) parent: Option<u32>,
    pub(crate) class_body: bool,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct BindingSlot {
    pub(crate) slot: u32,
    pub(crate) scope: u32,
    pub(crate) name: String,
    pub(crate) whole_scope: bool,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct BindingEvent {
    pub(crate) event: u32,
    pub(crate) slot: u32,
    pub(crate) target: u32,
    pub(crate) kind: ResolutionBindingEventKind,
    pub(crate) authored: Option<u32>,
    pub(crate) value_slot: Option<u32>,
    pub(crate) execution_scope: u32,
    pub(crate) entry_byte: usize,
    pub(crate) commit_byte: usize,
    pub(crate) phase: u32,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct BindingDirective {
    pub(crate) fact: ResolutionBindingDirectiveFact,
    pub(crate) name: String,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub(crate) struct PythonBindingRows {
    pub(crate) scopes: Vec<BindingScope>,
    pub(crate) slots: Vec<BindingSlot>,
    pub(crate) events: Vec<BindingEvent>,
    pub(crate) observations: Vec<ResolutionBindingObservationFact>,
    pub(crate) directives: Vec<BindingDirective>,
    pub(crate) guards: Vec<PythonNativeGuardFact>,
    pub(crate) site_guards: Vec<PythonNativeSiteGuardFact>,
    pub(crate) predicates: Vec<PythonNativePredicateFact>,
    pub(crate) imports: Vec<PythonNativeImportFact>,
    pub(crate) import_positions: Vec<(u32, u32, usize)>,
    pub(crate) loop_regions: Vec<(u32, std::ops::Range<usize>)>,
}

#[cfg(any(test, feature = "test-support"))]
impl super::cache_budget::RetainedBytes for PythonBindingRows {
    fn retained_bytes(&self) -> usize {
        let mut heap = super::cache_budget::RetainedHeap::default();
        heap.add(std::mem::size_of::<Self>());
        heap.vec(&self.scopes);
        heap.vec(&self.slots);
        heap.vec(&self.events);
        heap.vec(&self.observations);
        heap.vec(&self.directives);
        heap.vec(&self.guards);
        heap.vec(&self.site_guards);
        heap.vec(&self.predicates);
        heap.vec(&self.imports);
        heap.vec(&self.import_positions);
        heap.vec(&self.loop_regions);
        for slot in &self.slots {
            heap.add(slot.name.capacity());
        }
        for directive in &self.directives {
            heap.add(directive.name.capacity());
        }
        heap.total()
    }
}

const EVENT_KINDS: [ResolutionBindingEventKind; 12] = [
    ResolutionBindingEventKind::Parameter,
    ResolutionBindingEventKind::Assign,
    ResolutionBindingEventKind::Augment,
    ResolutionBindingEventKind::Delete,
    ResolutionBindingEventKind::Annotation,
    ResolutionBindingEventKind::Import,
    ResolutionBindingEventKind::Function,
    ResolutionBindingEventKind::Class,
    ResolutionBindingEventKind::Iteration,
    ResolutionBindingEventKind::With,
    ResolutionBindingEventKind::Exception,
    ResolutionBindingEventKind::Pattern,
];
const GUARD_KINDS: [PythonNativeGuardKind; 10] = [
    PythonNativeGuardKind::IfTrue,
    PythonNativeGuardKind::IfFalse,
    PythonNativeGuardKind::TryBody,
    PythonNativeGuardKind::ExceptArm,
    PythonNativeGuardKind::TryElse,
    PythonNativeGuardKind::Finally,
    PythonNativeGuardKind::LoopBody,
    PythonNativeGuardKind::LoopElse,
    PythonNativeGuardKind::MatchArm,
    PythonNativeGuardKind::UnknownControl,
];
const PREDICATE_KINDS: [PythonNativePredicateKind; 5] = [
    PythonNativePredicateKind::Name,
    PythonNativePredicateKind::Attribute,
    PythonNativePredicateKind::True,
    PythonNativePredicateKind::False,
    PythonNativePredicateKind::Unknown,
];
const IMPORT_FORMS: [PythonNativeImportForm; 3] = [
    PythonNativeImportForm::Module,
    PythonNativeImportForm::From,
    PythonNativeImportForm::Star,
];

const CURATED_SURFACES: [PythonNativeCuratedSurface; 3] = [
    PythonNativeCuratedSurface::Absent,
    PythonNativeCuratedSurface::Listed,
    PythonNativeCuratedSurface::Unreadable,
];
const WILDCARD_POLICIES: [PythonNativeWildcardPolicy; 3] = [
    PythonNativeWildcardPolicy::PublicNames,
    PythonNativeWildcardPolicy::Curated,
    PythonNativeWildcardPolicy::Unknown,
];
const EXPORT_OPERATION_KINDS: [PythonNativeExportOperationKind; 8] = [
    PythonNativeExportOperationKind::ReplaceList,
    PythonNativeExportOperationKind::ReplaceTuple,
    PythonNativeExportOperationKind::AugmentList,
    PythonNativeExportOperationKind::AugmentTuple,
    PythonNativeExportOperationKind::Extend,
    PythonNativeExportOperationKind::Append,
    PythonNativeExportOperationKind::Delete,
    PythonNativeExportOperationKind::Unknown,
];

fn code<T: PartialEq>(variants: &[T], value: &T) -> i64 {
    variants
        .iter()
        .position(|candidate| candidate == value)
        .expect("known source variant") as i64
}
fn variant<T: Copy>(variants: &[T], value: i64) -> rusqlite::Result<T> {
    usize::try_from(value)
        .ok()
        .and_then(|index| variants.get(index))
        .copied()
        .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn insert(tx: &Transaction<'_>, sql: &str, values: impl rusqlite::Params) -> Result<()> {
    tx.prepare_cached(sql)?.execute(values)?;
    Ok(())
}

#[doc(hidden)]
pub fn publish(
    tx: &Transaction<'_>,
    blob: i64,
    facts: &FileResolutionFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    if facts.scopes.is_empty() {
        return Ok(());
    }
    assert_eq!(
        facts.binding_events.len(),
        facts.binding_event_timings.len()
    );
    assert_eq!(
        facts.python_export_surfaces.len(),
        1,
        "one Python module surface"
    );
    let surface = facts.python_export_surfaces[0];
    assert_eq!(surface.module_scope.get(), 0);
    assert!(
        facts
            .scopes
            .iter()
            .any(|scope| scope.id == surface.module_scope)
    );
    let identifiers = facts
        .identifiers
        .iter()
        .map(|identifier| (identifier.site, identifier))
        .collect::<crate::hash::HashMap<_, _>>();
    insert(
        tx,
        "INSERT INTO python_binding_source(blob_id,format,export_curated,export_wildcard) VALUES(?1,?2,?3,?4)",
        params![
            blob,
            NATIVE_SOURCE_FORMAT,
            code(&CURATED_SURFACES, &surface.curated),
            code(&WILDCARD_POLICIES, &surface.wildcard_policy)
        ],
    )?;
    for scope in &facts.scopes {
        let parent = facts
            .scope_continuations
            .iter()
            .find(|row| row.scope == scope.id)
            .map_or(scope.parent, |row| row.parent);
        insert(
            tx,
            "INSERT INTO resolution_binding_scopes VALUES(?1,?2,?3)",
            params![blob, scope.id.get(), parent.map(|scope| scope.get())],
        )?;
    }
    for slot in &facts.binding_slots {
        let site = facts.sites[slot.declaration.index()];
        let identifier = identifiers[&slot.declaration];
        insert(
            tx,
            "INSERT INTO resolution_binding_slots VALUES(?1,?2,?3,?4,?5)",
            params![
                blob,
                slot.declaration.get(),
                site.scope.get(),
                facts.names[identifier.name.index()].spelling,
                slot.lookup == ResolutionBindingLookup::WholeScope
            ],
        )?;
    }
    for (event, timing) in facts
        .binding_events
        .iter()
        .zip(&facts.binding_event_timings)
    {
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled("temporal publication cancelled"));
        }
        assert_eq!(event.ordinal, timing.event);
        insert(
            tx,
            "INSERT INTO resolution_binding_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                blob,
                event.ordinal,
                event.slot.get(),
                event.target.get(),
                code(&EVENT_KINDS, &event.kind),
                event.authored_declaration.map(|site| site.get()),
                event.value.map(|slot| slot.get()),
                timing.execution_scope.get(),
                timing.entry_byte as i64,
                timing.commit_byte as i64,
                timing.commit_phase,
                event.source_reference.map(|site| site.get())
            ],
        )?;
    }
    for observation in &facts.binding_observations {
        insert(
            tx,
            "INSERT INTO resolution_binding_observations VALUES(?1,?2,?3,?4,?5)",
            params![
                blob,
                observation.reference.get(),
                observation.execution_scope.get(),
                observation.point_byte as i64,
                observation.kind == ResolutionBindingObservationKind::Deferred
            ],
        )?;
    }
    for directive in &facts.binding_directives {
        let identifier = identifiers[&directive.reference];
        insert(
            tx,
            "INSERT INTO resolution_binding_directives VALUES(?1,?2,?3,?4,?5)",
            params![
                blob,
                directive.reference.get(),
                i64::from(directive.kind == ResolutionBindingDirectiveKind::Nonlocal),
                facts.names[identifier.name.index()].spelling,
                directive.target.map(|site| site.get())
            ],
        )?;
    }
    for guard in &facts.python_guards {
        insert(
            tx,
            "INSERT INTO python_binding_guards VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                blob,
                guard.id,
                guard.parent,
                guard.site.get(),
                guard.execution_scope.get(),
                code(&GUARD_KINDS, &guard.kind),
                guard.arm_ordinal,
                guard.predicate.map(|site| site.get())
            ],
        )?;
    }
    for guard in &facts.python_site_guards {
        insert(
            tx,
            "INSERT INTO python_binding_site_guards VALUES(?1,?2,?3)",
            params![blob, guard.site.get(), guard.guard],
        )?;
    }
    for predicate in &facts.python_predicates {
        insert(
            tx,
            "INSERT INTO python_binding_predicates VALUES(?1,?2,?3,?4)",
            params![
                blob,
                predicate.predicate.get(),
                code(&PREDICATE_KINDS, &predicate.kind),
                predicate.operand.map(|site| site.get())
            ],
        )?;
    }
    for import in &facts.python_imports {
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled("Python source publication cancelled"));
        }
        let routes = facts
            .import_routes
            .iter()
            .filter(|route| route.site == import.import_site)
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 1, "one Python import route");
        let mut segments = facts
            .import_route_segments
            .iter()
            .filter(|segment| segment.import_site == import.import_site)
            .collect::<Vec<_>>();
        segments.sort_by_key(|segment| segment.ordinal);
        let route = segments
            .iter()
            .enumerate()
            .map(|(ordinal, segment)| {
                assert_eq!(segment.ordinal as usize, ordinal);
                facts.names[segment.name.index()].spelling.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            route.len(),
            import.module_segment_count as usize
                + usize::from(import.form == PythonNativeImportForm::From)
        );
        if import.form != PythonNativeImportForm::Star {
            let event = facts
                .binding_events
                .iter()
                .find(|event| Some(event.ordinal) == import.binding_event)
                .expect("named import binding event");
            assert_eq!(
                identifiers[&event.slot].name,
                routes[0].bound_name.expect("named import local name")
            );
        }
        insert(
            tx,
            "INSERT INTO python_binding_imports(blob_id,import_site,form,relative_level,module_segments,binding_event,route) VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7))",
            params![
                blob,
                import.import_site.get(),
                code(&IMPORT_FORMS, &import.form),
                import.relative_level,
                import.module_segment_count,
                import.binding_event,
                serde_json::to_string(&route).expect("string array serializes")
            ],
        )?;
    }
    let mut member_count = 0;
    for (ordinal, operation) in facts.python_export_operations.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled("Python source publication cancelled"));
        }
        assert_eq!(operation.ordinal as usize, ordinal);
        assert_eq!(operation.module_scope.get(), 0);
        let mut members = facts
            .python_export_members
            .iter()
            .filter(|member| member.operation_ordinal == operation.ordinal)
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.ordinal);
        member_count += members.len();
        // Unreadable literal lists can omit dynamic elements, leaving gaps in
        // member ordinals. Preserve their order, not invented dense positions.
        assert!(
            members
                .windows(2)
                .all(|pair| pair[0].ordinal < pair[1].ordinal)
        );
        let names = members
            .iter()
            .map(|member| facts.names[member.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        insert(
            tx,
            "INSERT INTO python_binding_export_operations(blob_id,ordinal,kind,readable,members) VALUES(?1,?2,?3,?4,jsonb(?5))",
            params![
                blob,
                operation.ordinal,
                code(&EXPORT_OPERATION_KINDS, &operation.kind),
                operation.readable,
                serde_json::to_string(&names).expect("string array serializes")
            ],
        )?;
    }
    assert_eq!(
        member_count,
        facts.python_export_members.len(),
        "export members have an operation"
    );
    Ok(())
}

/// One row in the selected revision's retained environment inputs.
/// The callback owns this row only; the store retains no workspace collection.
#[doc(hidden)]
#[derive(Debug)]
pub enum EnvironmentSourceRow {
    File {
        path: String,
        oid: String,
        blob: i64,
        curated: PythonNativeCuratedSurface,
        wildcard: PythonNativeWildcardPolicy,
    },
    ModuleSlot {
        path: String,
        slot: u32,
        name: String,
    },
    Import {
        path: String,
        site: u32,
        form: PythonNativeImportForm,
        relative_level: u32,
        module_segments: u32,
        local_name: String,
    },
    ImportSegment {
        path: String,
        site: u32,
        ordinal: u32,
        spelling: String,
    },
    ExportOperation {
        path: String,
        ordinal: u32,
        kind: PythonNativeExportOperationKind,
        readable: bool,
    },
    ExportMember {
        path: String,
        operation: u32,
        /// Dense array position, not the producer's sparse member ordinal.
        position: u32,
        name: String,
    },
}

pub(crate) const ENVIRONMENT_SOURCE_SQL: &str = r#"WITH selected AS MATERIALIZED (
 SELECT f.rel_path,f.blob_oid,b.id AS blob_id,s.format,
        s.export_curated,s.export_wildcard
 FROM workspace_file_versions f
 LEFT JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.parse_variant=x''
                  AND b.generation=f.generation
 LEFT JOIN python_binding_source s ON s.blob_id=b.id
 WHERE f.workspace_id=?1 AND f.lang='python' AND f.generation=?2
   AND f.input_kind='source' AND f.valid_from<=?3
   AND (f.valid_until IS NULL OR ?3<f.valid_until)
), inputs AS (
 SELECT 0 AS row_kind,rel_path,blob_oid,blob_id,format,
        export_curated AS a,export_wildcard AS b,NULL AS c,NULL AS d,
        NULL AS spelling FROM selected
 UNION ALL
 SELECT 1,s.rel_path,s.blob_oid,s.blob_id,s.format,
        slots.slot,NULL,NULL,NULL,slots.name
 FROM selected s CROSS JOIN resolution_binding_slots slots ON slots.blob_id=s.blob_id
 WHERE s.format=?4 AND slots.scope=0
 UNION ALL
 SELECT 2,s.rel_path,s.blob_oid,s.blob_id,s.format,
        i.import_site,i.form,i.relative_level,i.module_segments,
        CASE WHEN i.form=2 THEN '' ELSE slots.name END
 FROM selected s CROSS JOIN python_binding_imports i ON i.blob_id=s.blob_id
 LEFT JOIN resolution_binding_events e
   ON e.blob_id=i.blob_id AND e.event=i.binding_event
 LEFT JOIN resolution_binding_slots slots
   ON slots.blob_id=e.blob_id AND slots.slot=e.slot
 WHERE s.format=?4
 UNION ALL
 SELECT 3,s.rel_path,s.blob_oid,s.blob_id,s.format,
        i.import_site,CAST(j.key AS INTEGER),NULL,NULL,j.value
 FROM selected s CROSS JOIN python_binding_imports i ON i.blob_id=s.blob_id
 JOIN json_each(i.route) j
 WHERE s.format=?4
 UNION ALL
 SELECT 4,s.rel_path,s.blob_oid,s.blob_id,s.format,
        o.ordinal,o.kind,o.readable,NULL,NULL
 FROM selected s CROSS JOIN python_binding_export_operations o ON o.blob_id=s.blob_id
 WHERE s.format=?4
 UNION ALL
 SELECT 5,s.rel_path,s.blob_oid,s.blob_id,s.format,
        o.ordinal,CAST(j.key AS INTEGER),NULL,NULL,j.value
 FROM selected s CROSS JOIN python_binding_export_operations o ON o.blob_id=s.blob_id
 JOIN json_each(o.members) j
 WHERE s.format=?4
)
SELECT * FROM inputs ORDER BY rel_path,row_kind,a,b"#;

pub(crate) const ENVIRONMENT_SOURCE_CANCELLED: &str = "Python environment source read cancelled";

/// Stream a selected revision once. Missing publication is an error, never an
/// excluded file: omitting it could certify an incomplete environment.
pub(crate) fn read_environment_source_rows(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    cancellation: &CancellationToken,
    mut consume: impl FnMut(&Connection, EnvironmentSourceRow) -> Result<()>,
) -> Result<()> {
    assert_eq!(snapshot.lang, "python");
    let mut statement = conn.prepare_cached(ENVIRONMENT_SOURCE_SQL)?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision,
        NATIVE_SOURCE_FORMAT
    ])?;
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled(ENVIRONMENT_SOURCE_CANCELLED));
        }
        let path: String = row.get(1)?;
        let value = match row.get::<_, u32>(0)? {
            0 => {
                let oid: String = row.get(2)?;
                let blob: Option<i64> = row.get(3)?;
                let format: Option<i64> = row.get(4)?;
                let Some(blob) = blob.filter(|_| format == Some(NATIVE_SOURCE_FORMAT)) else {
                    return Err(StoreError::missing_required_source_facts(format!(
                        "python_retained_input_unavailable: path={path:?} oid={oid:?} blob={blob:?} format={format:?}"
                    )));
                };
                EnvironmentSourceRow::File {
                    path,
                    oid,
                    blob,
                    curated: variant(&CURATED_SURFACES, row.get(5)?)?,
                    wildcard: variant(&WILDCARD_POLICIES, row.get(6)?)?,
                }
            }
            1 => EnvironmentSourceRow::ModuleSlot {
                path,
                slot: row.get(5)?,
                name: row.get(9)?,
            },
            2 => EnvironmentSourceRow::Import {
                path,
                site: row.get(5)?,
                form: variant(&IMPORT_FORMS, row.get(6)?)?,
                relative_level: row.get(7)?,
                module_segments: row.get(8)?,
                local_name: row.get(9)?,
            },
            3 => EnvironmentSourceRow::ImportSegment {
                path,
                site: row.get(5)?,
                ordinal: row.get(6)?,
                spelling: row.get(9)?,
            },
            4 => EnvironmentSourceRow::ExportOperation {
                path,
                ordinal: row.get(5)?,
                kind: variant(&EXPORT_OPERATION_KINDS, row.get(6)?)?,
                readable: row.get(7)?,
            },
            5 => EnvironmentSourceRow::ExportMember {
                path,
                operation: row.get(5)?,
                position: row.get(6)?,
                name: row.get(9)?,
            },
            _ => unreachable!("environment source query row kind"),
        };
        consume(conn, value)?;
    }
    if cancellation.is_cancelled() {
        return Err(StoreError::cancelled(ENVIRONMENT_SOURCE_CANCELLED));
    }
    Ok(())
}

impl AnalyzerStore {
    /// Read retained environment inputs with one SQL statement for this revision.
    #[doc(hidden)]
    pub fn with_python_environment_source_rows(
        &self,
        snapshot: WorkspaceSnapshotId,
        cancellation: CancellationToken,
        consume: impl FnMut(&Connection, EnvironmentSourceRow) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        self.conn.execute(move |conn| {
            read_environment_source_rows(conn, &snapshot, &cancellation, consume)
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PythonBindingRows {
    pub(crate) fn load(
        conn: &Connection,
        cache: &super::cache_budget::StoreCacheBudget,
        blob: i64,
        known_oid: Option<git2::Oid>,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::sync::Arc<Self>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }

        // Row ids can be reused after deletion. The content and producer, not
        // the row id, determine the validity of these unit-local facts.
        let identity = if let Some(oid) = known_oid {
            conn.query_row(
                "SELECT format FROM python_binding_source WHERE blob_id=?1",
                [blob],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|format| (oid, format))
        } else {
            let selected = conn.query_row(
                "SELECT blobs.blob_oid,source.format FROM blobs JOIN python_binding_source source ON source.blob_id=blobs.id WHERE blobs.id=?1 AND blobs.lang='python'",
                [blob], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            ).optional()?;
            match selected {
                Some((oid, format)) => Some((git2::Oid::from_str(&oid)?, format)),
                None => None,
            }
        };
        let Some((oid, format)) = identity else {
            return Ok(None);
        };
        if format != NATIVE_SOURCE_FORMAT {
            return Ok(None);
        }
        let blob_oid = *oid
            .as_bytes()
            .first_chunk::<20>()
            .expect("SHA-1 content identity");
        if let Some(rows) = cache.python_binding_rows(blob_oid, format) {
            return Ok((!cancellation.is_cancelled()).then_some(rows));
        }
        let mut result = Self::default();
        macro_rules! read {
            ($sql:expr,$field:ident,$convert:expr) => {{
                let mut statement = conn.prepare_cached($sql)?;
                let rows = statement.query_map([blob], $convert)?;
                for row in rows {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    result.$field.push(row?);
                }
            }};
        }
        read!(
            "SELECT scopes.scope,scopes.parent_scope,EXISTS(
                SELECT 1 FROM resolution_member_scope_properties properties
                JOIN resolution_node_catalog nodes ON nodes.blob_id=properties.blob_id
                    AND nodes.local_key=properties.scope_head_node_key
                WHERE properties.blob_id=?1 AND properties.scope_kind='type_body'
                    AND nodes.source_scope=scopes.scope)
             FROM resolution_binding_scopes scopes WHERE scopes.blob_id=?1 ORDER BY scopes.scope",
            scopes,
            |r| Ok(BindingScope {
                scope: r.get(0)?,
                parent: r.get(1)?,
                class_body: r.get(2)?
            })
        );
        read!(
            "SELECT slot,scope,name,whole_scope FROM resolution_binding_slots WHERE blob_id=?1 ORDER BY slot",
            slots,
            |r| Ok(BindingSlot {
                slot: r.get(0)?,
                scope: r.get(1)?,
                name: r.get(2)?,
                whole_scope: r.get(3)?
            })
        );
        read!(
            "SELECT event,slot,target,kind,authored,value_slot,execution_scope,entry_byte,commit_byte,phase FROM resolution_binding_events WHERE blob_id=?1 ORDER BY commit_byte DESC,phase DESC,event DESC",
            events,
            |r| Ok(BindingEvent {
                event: r.get(0)?,
                slot: r.get(1)?,
                target: r.get(2)?,
                kind: variant(&EVENT_KINDS, r.get(3)?)?,
                authored: r.get(4)?,
                value_slot: r.get(5)?,
                execution_scope: r.get(6)?,
                entry_byte: r.get(7)?,
                commit_byte: r.get(8)?,
                phase: r.get(9)?
            })
        );
        read!(
            "SELECT reference,execution_scope,point_byte,deferred FROM resolution_binding_observations WHERE blob_id=?1 ORDER BY reference",
            observations,
            |r| Ok(ResolutionBindingObservationFact {
                reference: ResolutionSiteId::new(r.get(0)?),
                execution_scope: ResolutionScopeId::new(r.get(1)?),
                point_byte: r.get(2)?,
                kind: if r.get::<_, bool>(3)? {
                    ResolutionBindingObservationKind::Deferred
                } else {
                    ResolutionBindingObservationKind::Immediate
                }
            })
        );
        read!(
            "SELECT reference,kind,target,name FROM resolution_binding_directives WHERE blob_id=?1 ORDER BY reference",
            directives,
            |r| Ok(BindingDirective {
                fact: ResolutionBindingDirectiveFact {
                    reference: ResolutionSiteId::new(r.get(0)?),
                    kind: if r.get::<_, i64>(1)? == 0 {
                        ResolutionBindingDirectiveKind::Global
                    } else {
                        ResolutionBindingDirectiveKind::Nonlocal
                    },
                    target: r.get::<_, Option<u32>>(2)?.map(ResolutionSiteId::new)
                },
                name: r.get(3)?
            })
        );
        read!(
            "SELECT guard,parent,site,execution_scope,kind,arm,predicate FROM python_binding_guards WHERE blob_id=?1 ORDER BY guard",
            guards,
            |r| Ok(PythonNativeGuardFact {
                id: r.get(0)?,
                parent: r.get(1)?,
                site: ResolutionSiteId::new(r.get(2)?),
                execution_scope: ResolutionScopeId::new(r.get(3)?),
                kind: variant(&GUARD_KINDS, r.get(4)?)?,
                arm_ordinal: r.get(5)?,
                predicate: r.get::<_, Option<u32>>(6)?.map(ResolutionSiteId::new)
            })
        );
        read!(
            "SELECT site,guard FROM python_binding_site_guards WHERE blob_id=?1 ORDER BY site",
            site_guards,
            |r| Ok(PythonNativeSiteGuardFact {
                site: ResolutionSiteId::new(r.get(0)?),
                guard: r.get(1)?
            })
        );
        read!(
            "SELECT predicate,kind,operand FROM python_binding_predicates WHERE blob_id=?1 ORDER BY predicate",
            predicates,
            |r| Ok(PythonNativePredicateFact {
                predicate: ResolutionSiteId::new(r.get(0)?),
                kind: variant(&PREDICATE_KINDS, r.get(1)?)?,
                operand: r.get::<_, Option<u32>>(2)?.map(ResolutionSiteId::new)
            })
        );
        read!(
            "SELECT import_site,form,relative_level,module_segments,binding_event FROM python_binding_imports WHERE blob_id=?1 ORDER BY import_site",
            imports,
            |r| Ok(PythonNativeImportFact {
                import_site: ResolutionSiteId::new(r.get(0)?),
                form: variant(&IMPORT_FORMS, r.get(1)?)?,
                relative_level: r.get(2)?,
                module_segment_count: r.get(3)?,
                binding_event: r.get(4)?
            })
        );
        read!(
            "SELECT import_site,root_scope,position FROM resolution_root_imports WHERE blob_id=?1 AND position IS NOT NULL ORDER BY import_site",
            import_positions,
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        );
        // The structured loop node spans include targets, iterable/condition
        // headers and bodies. Guard chains alone cover only the body/else arms.
        {
            use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
            let mut statement = conn.prepare_cached(
                "WITH owners AS MATERIALIZED (
                    SELECT nodes.source_scope,declaration.start_byte,declaration.end_byte
                    FROM resolution_member_scope_properties properties
                    JOIN resolution_node_catalog nodes ON nodes.blob_id=properties.blob_id
                        AND nodes.local_key=properties.scope_head_node_key
                    JOIN resolution_semantic_sites semantic ON semantic.blob_id=properties.blob_id
                        AND semantic.semantic_key=properties.definition_semantic_key
                        AND semantic.semantic_role='definition'
                    JOIN source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id
                        AND bridge.source_site=semantic.source_site
                    JOIN source_declarations declaration ON declaration.blob_id=bridge.blob_id
                        AND declaration.declaration_id=bridge.declaration_id
                    WHERE properties.blob_id=?1
                 )
                 SELECT coalesce((SELECT source_scope FROM owners
                     WHERE start_byte<=node.value->>3 AND end_byte>=node.value->>4
                     ORDER BY end_byte-start_byte LIMIT 1),root.scope),
                     node.value->>3,node.value->>4
                 FROM source_structural_facts facts
                 JOIN resolution_binding_scopes root ON root.blob_id=facts.blob_id
                     AND root.parent_scope IS NULL
                 CROSS JOIN json_each(facts.nodes) node
                 WHERE facts.blob_id=?1 AND node.value->>0 IN (?2,?3)",
            )?;
            let loops = statement.query_map(
                params![
                    blob,
                    NormalizedKind::ForLoop as u8,
                    NormalizedKind::WhileLoop as u8
                ],
                |row| Ok((row.get(0)?, row.get(1)?..row.get(2)?)),
            )?;
            for region in loops {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                result.loop_regions.push(region?);
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let result = std::sync::Arc::new(result);
        cache.insert_python_binding_rows(blob_oid, format, std::sync::Arc::clone(&result));
        Ok(Some(result))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl AnalyzerStore {
    #[doc(hidden)]
    pub fn python_binding_source_is_current(&self, blob: i64) -> Result<bool> {
        self.conn.execute(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT format FROM python_binding_source WHERE blob_id=?1",
                    [blob],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                == Some(NATIVE_SOURCE_FORMAT))
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl super::python_unit_summaries::PythonEnvironmentPublication {
    /// Inspect the dormant retained source contract after a real publication.
    /// SQL chooses the selected file versions; no workspace index survives this call.
    pub fn render_binding_inputs(&self, revision: i64) -> Result<String> {
        use std::fmt::Write;
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        let profile = self.profile.clone();
        let cache = self.store.cache_budget.clone();
        self.store.conn.execute(move |conn| {
            let summary = crate::analyzer::store::python_unit_summaries::selected_binding_summary(conn,&snapshot,&profile)?
                .expect("reconciled selected Python environment");
            let mut statement = conn.prepare_cached(
                "SELECT rel_path,blob_id FROM resolution_unit_summary_members
                 WHERE summary_id=?1 ORDER BY rel_path")?;
            let selected = statement.query_map([summary],
                |row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut output = String::new();
            for (path,blob) in selected {
                let rows = crate::analyzer::store::python_binding_rows::PythonBindingRows::load(
                    conn,&cache,blob,None,&CancellationToken::default())?.expect("native temporal source format");
                writeln!(output,"{path}").expect("string output");
                for row in &rows.scopes { writeln!(output,"scope {} parent={:?}",row.scope,row.parent).unwrap(); }
                for row in &rows.slots { writeln!(output,"slot {} scope={} name={} whole={}",row.slot,row.scope,row.name,row.whole_scope).unwrap(); }
                for row in &rows.events { writeln!(output,"event {} slot={} target={} kind={:?} authored={:?} value={:?} execution={} entry={} commit={}:{}",row.event,row.slot,row.target,row.kind,row.authored,row.value_slot,row.execution_scope,row.entry_byte,row.commit_byte,row.phase).unwrap(); }
                for row in &rows.observations { writeln!(output,"observe {} scope={} point={} {:?}",row.reference.get(),row.execution_scope.get(),row.point_byte,row.kind).unwrap(); }
                for row in &rows.directives { writeln!(output,"directive {} {:?} target={:?}",row.fact.reference.get(),row.fact.kind,row.fact.target).unwrap(); }
                for row in &rows.guards { writeln!(output,"guard {} parent={:?} site={} scope={} {:?} arm={} predicate={:?}",row.id,row.parent,row.site.get(),row.execution_scope.get(),row.kind,row.arm_ordinal,row.predicate).unwrap(); }
                for row in &rows.site_guards { writeln!(output,"guarded {} guard={}",row.site.get(),row.guard).unwrap(); }
                for row in &rows.predicates { writeln!(output,"predicate {} {:?} operand={:?}",row.predicate.get(),row.kind,row.operand).unwrap(); }
                for row in &rows.imports { writeln!(output,"import {} {:?} level={} segments={} event={:?}",row.import_site.get(),row.form,row.relative_level,row.module_segment_count,row.binding_event).unwrap(); }
                if let Some(slot) = rows.slots.iter().find(|slot| rows.scopes.iter()
                    .any(|scope|scope.scope == slot.scope && scope.parent.is_none())) {
                    use crate::analyzer::store::resolution_operation::python_lexical;
                    use crate::analyzer::resolution::temporal_binding::SessionBudget;
                    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
                    let cancellation = CancellationToken::default();
                    let boundary = crate::analyzer::resolution::with_bounded_resolution_session(
                        ReceiverAnalysisBudget::default(),&cancellation,|session| {
                            let mode = if matches!(profile.observation,
                                super::python_unit_summaries::PythonSummaryObservation::Typing) {
                                python_lexical::PythonBindingProfile::Typing
                            } else {python_lexical::PythonBindingProfile::Runtime};
                            let mut state = python_lexical::module_selection(&rows,slot.scope,&slot.name,
                                mode,python_lexical::PythonBindingProofs::default());
                            python_lexical::select_lexical(&mut state,&rows,
                                &mut SessionBudget{session,cancellation:&cancellation},&cancellation)?;
                            Ok(format!("{:?}",state.selection))
                        })?;
                    writeln!(output,"module boundary {} {boundary:?}",slot.name).unwrap();
                }
            }
            Ok(output)
        })
    }

    /// Native lexical validation only. This entry does not enable a production
    /// consumer. Route/target publication is exercised by the M4-3b source entry.
    pub fn temporal_binding_trace(
        &self,
        revision: i64,
        path: &str,
        point: usize,
        name: &str,
    ) -> Result<String> {
        use crate::analyzer::resolution::temporal_binding::SessionBudget;
        use crate::analyzer::store::resolution_operation::python_lexical;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        let profile = self.profile.clone();
        let path = path.to_owned();
        let name = name.to_owned();
        let typing = matches!(
            self.profile.observation,
            crate::analyzer::store::python_unit_summaries::PythonSummaryObservation::Typing
        );
        let cache = self.store.cache_budget.clone();
        self.store.conn.execute(move |conn| {
            let summary = crate::analyzer::store::python_unit_summaries::selected_binding_summary(conn,&snapshot,&profile)?
                .expect("reconciled selected Python environment");
            let blob = conn.query_row("SELECT blob_id FROM resolution_unit_summary_members WHERE summary_id=?1 AND rel_path=?2",
                rusqlite::params![summary,path],|row|row.get(0))?;
            let cancellation = CancellationToken::default();
            let rows = crate::analyzer::store::python_binding_rows::PythonBindingRows::load(
                conn,&cache,blob,None,&cancellation)?.expect("native temporal source format");
            let observation = rows.observations.iter().find(|row|row.point_byte == point)
                .expect("exact retained reference position");
            crate::analyzer::resolution::with_bounded_resolution_session(
                ReceiverAnalysisBudget::default(),&cancellation,|session| {
                    let profile = if typing { python_lexical::PythonBindingProfile::Typing }
                        else { python_lexical::PythonBindingProfile::Runtime };
                    let mut state = python_lexical::lexical_selection(&rows,
                        observation.reference.get(),&name,profile,
                        python_lexical::PythonBindingProofs::default()).expect("lexical observation");
                    let mut budget = SessionBudget {session,cancellation:&cancellation};
                    python_lexical::select_lexical(&mut state,&rows,&mut budget,&cancellation)?;
                    let definitions = state.selection.selected.iter().filter_map(|selected|
                        rows.events.iter().find(|event|event.event == selected.occurrence))
                        .map(|event|format!("{:?}@{}:{}",event.kind,event.entry_byte,event.commit_byte))
                        .collect::<Vec<_>>();
                    Ok(format!("definitions={definitions:?} rank={:?} {:?}",python_lexical::TemporalRank(0),state.selection))
                }).map(|result|format!("{result:?}"))
        })
    }
}

#[cfg(test)]
mod cache_tests {
    use super::super::cache_budget::{RetainedBytes, StoreCacheBudget};
    use super::*;
    use std::sync::Arc;

    #[test]
    fn binding_cache_reads_current_identity_and_only_retains_complete_loads() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let cache = store.cache_budget.clone();
        store
            .conn
            .execute(move |conn| -> Result<()> {
                conn.execute(
                    "INSERT INTO blobs(blob_oid,lang) VALUES(?1,'python')",
                    ["a".repeat(40)],
                )?;
                let blob = conn.last_insert_rowid();
                let scope = ResolutionScopeId::new(0);
                let site = ResolutionSiteId::new(42);
                let facts = FileResolutionFacts {
                    scopes: vec![ResolutionScopeFact { id: scope, parent: None, owner: None,
                        kind: ResolutionScopeKind::CompilationUnit, inheritance: ResolutionScopeInheritance::Root,
                        start_byte: 0, end_byte: 1 }],
                    names: ["second", "first", "package", "module"].into_iter().enumerate().map(|(id, spelling)| ResolutionNameFact { id: ResolutionNameId::new(id as u32), spelling: spelling.to_owned() }).collect(),
                    python_export_surfaces: vec![PythonNativeExportSurfaceFact { module_scope: scope,
                        curated: PythonNativeCuratedSurface::Unreadable, wildcard_policy: PythonNativeWildcardPolicy::Unknown }],
                    python_export_operations: vec![
                        PythonNativeExportOperationFact { ordinal: 0, site, module_scope: scope, kind: PythonNativeExportOperationKind::ReplaceList, readable: false },
                        PythonNativeExportOperationFact { ordinal: 1, site, module_scope: scope, kind: PythonNativeExportOperationKind::Unknown, readable: false },
                    ],
                    // Dynamic elements in an unreadable list leave ordinal gaps.
                    python_export_members: vec![
                        PythonNativeExportMemberFact { operation_ordinal: 0, ordinal: 3, name: ResolutionNameId::new(1), literal_site: site },
                        PythonNativeExportMemberFact { operation_ordinal: 0, ordinal: 1, name: ResolutionNameId::new(0), literal_site: site },
                    ],
                    python_imports: vec![PythonNativeImportFact { import_site: site, form: PythonNativeImportForm::Star, relative_level: 1, module_segment_count: 2, binding_event: None }],
                    import_routes: vec![ResolutionImportRouteFact { site, root_scope: scope, kind: ResolutionImportRouteKind::Star, bound_name: None }],
                    import_route_segments: vec![
                        ResolutionImportRouteSegmentFact { import_site: site, ordinal: 1, name: ResolutionNameId::new(3) },
                        ResolutionImportRouteSegmentFact { import_site: site, ordinal: 0, name: ResolutionNameId::new(2) },
                    ],
                    ..FileResolutionFacts::default()
                };
                let tx = conn.unchecked_transaction()?;
                publish(&tx, blob, &facts, &CancellationToken::default())?;
                tx.commit()?;
                let snapshot = WorkspaceSnapshotId {
                    workspace_id: super::super::WorkspaceId("e".repeat(64)),
                    lang: "python".to_owned(), generation: super::super::GenerationId(0), revision: 1,
                };
                conn.execute("INSERT INTO workspace_revisions VALUES(?1,'python',0,1)", [snapshot.workspace_id.as_str()])?;
                for path in ["a.py", "alias.py"] {
                    conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from,valid_until) VALUES(?1,'python',0,?2,?3,?4,1,2)", params![snapshot.workspace_id.as_str(), path, "a".repeat(40), "0".repeat(64)])?;
                }
                let mut decoded = Vec::new();
                read_environment_source_rows(conn, &snapshot, &CancellationToken::default(), |_, row| { decoded.push(format!("{row:?}")); Ok(()) })?;
                assert_eq!(decoded.len(), 16, "two path-sensitive copies, including empty operation and complete route");
                assert!(decoded[0].contains("a.py"));
                assert!(decoded[0].contains("curated: Unreadable, wildcard: Unknown"));
                assert!(decoded[8].contains("alias.py"));
                assert!(decoded[2].contains("ordinal: 0, spelling: \"package\""));
                assert!(decoded[3].contains("ordinal: 1, spelling: \"module\""));
                assert!(decoded[4].contains("kind: ReplaceList, readable: false"));
                assert!(decoded[5].contains("kind: Unknown, readable: false"));
                assert!(decoded[6].contains("position: 0, name: \"second\""));
                assert!(decoded[7].contains("position: 1, name: \"first\""));
                let mut later = snapshot.clone(); later.revision = 2;
                let mut later_rows = 0;
                read_environment_source_rows(conn, &later, &CancellationToken::default(), |_, _| { later_rows += 1; Ok(()) })?;
                assert_eq!(later_rows, 0, "closed membership is not selected");
                let cancelled = CancellationToken::cancel_after_checks_for_test(1);
                let error = read_environment_source_rows(conn, &snapshot, &cancelled, |_, _| Ok(())).unwrap_err().context("reading selected environment");
                assert!(error.is_cancelled(), "{error}");
                assert!(cancelled.is_cancelled());
                for sql in [
                    "UPDATE python_binding_source SET export_curated=3",
                    "UPDATE python_binding_source SET export_wildcard=-1",
                    "UPDATE python_binding_imports SET route=jsonb('{}')",
                    "UPDATE python_binding_export_operations SET members=jsonb('{}')",
                    "UPDATE python_binding_export_operations SET kind=8",
                    "UPDATE python_binding_export_operations SET readable=2",
                ] { assert!(conn.execute(sql, []).is_err(), "accepted {sql}"); }
                let interrupted = CancellationToken::cancel_after_checks_for_test(2);
                assert!(PythonBindingRows::load(conn, &cache, blob, None, &interrupted)?.is_none());
                assert!(
                    interrupted.is_cancelled(),
                    "the row read reached the cancellation checkpoint"
                );
                assert_eq!(cache.weighted_bytes(), 0);
                let cancellation = CancellationToken::default();
                let first =
                    PythonBindingRows::load(conn, &cache, blob, None, &cancellation)?.unwrap();
                assert_eq!(first.scopes[0].scope, 0);
                assert!(cache.weighted_bytes() > first.retained_bytes() as u64);
                let again =
                    PythonBindingRows::load(conn, &cache, blob, None, &cancellation)?.unwrap();
                assert!(Arc::ptr_eq(&first, &again));
                let hit_cancel = CancellationToken::cancel_after_checks_for_test(2);
                assert!(PythonBindingRows::load(conn, &cache, blob, None, &hit_cancel)?.is_none());
                assert!(hit_cancel.is_cancelled());
                conn.execute(
                    "UPDATE python_binding_source SET format=?1 WHERE blob_id=?2",
                    params![NATIVE_SOURCE_FORMAT + 1, blob],
                )?;
                assert!(
                    PythonBindingRows::load(conn, &cache, blob, None, &cancellation)?.is_none()
                );
                let error = read_environment_source_rows(conn, &snapshot, &cancellation, |_, _| Ok(())).unwrap_err();
                assert!(error.is_missing_required_source_facts());
                assert!(error.to_string().contains("a.py"));
                conn.execute("DELETE FROM blobs WHERE id=?1", [blob])?;
                let error = read_environment_source_rows(conn, &snapshot, &cancellation, |_, _| Ok(())).unwrap_err();
                assert!(error.is_missing_required_source_facts());
                assert!(error.to_string().contains("blob=None"));
                conn.execute(
                    "INSERT INTO blobs(blob_oid,lang) VALUES(?1,'python')",
                    ["b".repeat(40)],
                )?;
                assert_eq!(
                    conn.last_insert_rowid(),
                    blob,
                    "SQLite reused the deleted row id"
                );
                conn.execute(
                    "INSERT INTO python_binding_source VALUES(?1,?2,0,0)",
                    params![blob, NATIVE_SOURCE_FORMAT],
                )?;
                conn.execute(
                    "INSERT INTO resolution_binding_scopes VALUES(?1,7,NULL)",
                    [blob],
                )?;
                let replacement =
                    PythonBindingRows::load(conn, &cache, blob, None, &cancellation)?.unwrap();
                assert_eq!(replacement.scopes[0].scope, 7);
                assert!(!Arc::ptr_eq(&first, &replacement));
                let tiny = StoreCacheBudget::new(1);
                let uncached =
                    PythonBindingRows::load(conn, &tiny, blob, None, &cancellation)?.unwrap();
                let reread =
                    PythonBindingRows::load(conn, &tiny, blob, None, &cancellation)?.unwrap();
                assert_eq!(uncached.scopes[0].scope, reread.scopes[0].scope);
                assert!(!Arc::ptr_eq(&uncached, &reread));
                assert_eq!(tiny.weighted_bytes(), 0);
                Ok(())
            })
            .unwrap();
    }
}
