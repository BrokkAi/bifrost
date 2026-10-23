//! Retained source inputs for one selected Python blob. All returned collections
//! belong to one query; this module never retains a module or workspace index.
#[cfg(any(test, feature = "test-support"))]
use super::AnalyzerStore;
use super::{Result, StoreError};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::resolution_facts::*;
#[cfg(any(test, feature = "test-support"))]
use rusqlite::{Connection, OptionalExtension};
use rusqlite::{Transaction, params};

// Format 2 added typed slots and authored member kinds. Format 3 also requires
// lexical root references, preventing cached reads from bypassing temporal closure.
// Format 5 adds direct alias observations and positioned lookup requests.
// Format 6 also requires member role/base inputs and compiler proxy contexts.
// Format 7 fixes authored parameter/field type owners and positional receiver roles.
// Format 7 also publishes direct assignment Value properties for typed reads.
// This format is frozen because production has no Python resolution publication path:
// selected_resolution_overlay_inputs_excluding does not admit Python, and
// PythonEnvironmentPublication is test-support only. The admission point ends
// this freeze; #6108 sets the production format once.
pub(crate) const NATIVE_SOURCE_FORMAT: i64 = 7;
// Dormant inputs also retain dynamic operations and exact/prefix/Any names.

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct BindingScope {
    pub(crate) scope: u32,
    pub(crate) parent: Option<u32>,
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

fn code<T: PartialEq>(variants: &[T], value: &T) -> i64 {
    variants
        .iter()
        .position(|candidate| candidate == value)
        .expect("known source variant") as i64
}
#[cfg(any(test, feature = "test-support"))]
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
    let identifiers = facts
        .identifiers
        .iter()
        .map(|identifier| (identifier.site, identifier))
        .collect::<crate::hash::HashMap<_, _>>();
    insert(
        tx,
        "INSERT INTO python_binding_source VALUES(?1,?2)",
        params![blob, NATIVE_SOURCE_FORMAT],
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
            return Err(StoreError::new("temporal publication cancelled"));
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
        insert(
            tx,
            "INSERT INTO python_binding_imports VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                blob,
                import.import_site.get(),
                code(&IMPORT_FORMS, &import.form),
                import.relative_level,
                import.module_segment_count,
                import.binding_event
            ],
        )?;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
impl PythonBindingRows {
    pub(crate) fn load(
        conn: &Connection,
        blob: i64,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self>> {
        if conn
            .query_row(
                "SELECT format FROM python_binding_source WHERE blob_id=?1",
                [blob],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            != Some(NATIVE_SOURCE_FORMAT)
        {
            return Ok(None);
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
            "SELECT scope,parent_scope FROM resolution_binding_scopes WHERE blob_id=?1 ORDER BY scope",
            scopes,
            |r| Ok(BindingScope {
                scope: r.get(0)?,
                parent: r.get(1)?
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
                    conn,blob,&CancellationToken::default())?.expect("native temporal source format");
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
        self.store.conn.execute(move |conn| {
            let summary = crate::analyzer::store::python_unit_summaries::selected_binding_summary(conn,&snapshot,&profile)?
                .expect("reconciled selected Python environment");
            let blob = conn.query_row("SELECT blob_id FROM resolution_unit_summary_members WHERE summary_id=?1 AND rel_path=?2",
                rusqlite::params![summary,path],|row|row.get(0))?;
            let cancellation = CancellationToken::default();
            let rows = crate::analyzer::store::python_binding_rows::PythonBindingRows::load(
                conn,blob,&cancellation)?.expect("native temporal source format");
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
