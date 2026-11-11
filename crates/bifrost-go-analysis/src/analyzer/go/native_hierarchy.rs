//! Trial-only selected Go hierarchy adapter.
use super::GoAnalyzer;
use brokk_bifrost_analysis::CodeUnitIndex;
use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
use brokk_bifrost_analysis::analyzer::i_analyzer::{
    QueryReadReceipt, scope_filter_descendant_answer,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoForwardEmptyInterfaceScan;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::{
    GoHierarchyDefinitionMatch, GoHierarchyHydration, SelectedNativeDefinition,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperation, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome,
};
use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
    SelectedResolutionLanguage, SelectedResolutionStale, SelectedResolutionUnavailable,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::usages::member_family::{
    MemberFamilyAnswer, MemberFamilyCompleteness,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_core::analyzer::capabilities::{
    Cancelled, DescendantIndexScope, HierarchyAnswer, HierarchyOpenReason, HierarchyQuery,
    MemberFamilyAncestors,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};
use brokk_bifrost_core::analyzer::structural::resolution::{
    MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use std::collections::HashMap;

#[cfg(any(test, feature = "test-support"))]
mod forward_scan_probe {
    use std::cell::Cell;

    thread_local! {
        static SCANS: Cell<usize> = const { Cell::new(0) };
        static INSERTS: Cell<usize> = const { Cell::new(0) };
        static STOP_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn scanned(
        session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) {
        SCANS.set(SCANS.get() + 1);
        if STOP_NEXT.replace(false) {
            assert!(!session.scope_steps(usize::MAX));
        }
    }

    pub(super) fn inserted() {
        INSERTS.set(INSERTS.get() + 1);
    }

    pub(super) fn take() -> (usize, usize) {
        (SCANS.replace(0), INSERTS.replace(0))
    }

    pub(super) fn stop_next() {
        STOP_NEXT.set(true);
    }
}

#[cfg(any(test, feature = "test-support"))]
mod family_positive_stop_probe {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use brokk_bifrost_core::analyzer::usages::resolution_session::{
        BoundedResolution, ResolutionSession,
    };
    use std::cell::Cell;

    thread_local! {
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
        static ARMED: Cell<Option<bool>> = const { Cell::new(None) };
        static FIRED: Cell<Option<ReceiverBudgetLimit>> = const { Cell::new(None) };
    }

    pub(super) fn arm(inverse: bool) {
        assert!(
            !ACTIVE.replace(true),
            "family positive probe already active"
        );
        assert!(ARMED.replace(Some(inverse)).is_none());
        FIRED.set(None);
    }

    pub(super) fn after_positive(inverse: bool, session: &ResolutionSession) {
        if ARMED.get() == Some(inverse) {
            ARMED.set(None);
            assert!(!session.scope_steps(usize::MAX));
            let BoundedResolution::Exceeded { limit, .. } = session.finish(()) else {
                panic!("family positive probe did not latch a budget stop");
            };
            FIRED.set(Some(limit));
        }
    }

    pub(super) fn fired_limit() -> Option<ReceiverBudgetLimit> {
        FIRED.get()
    }

    pub(super) fn clear() -> bool {
        let consumed = ARMED.replace(None).is_none();
        ACTIVE.set(false);
        FIRED.set(None);
        consumed
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct GoFamilyPositiveStopProbe(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(any(test, feature = "test-support"))]
impl GoFamilyPositiveStopProbe {
    pub fn arm_inverse() -> Self {
        family_positive_stop_probe::arm(true);
        Self(std::marker::PhantomData)
    }

    pub fn fired_limit(
        &self,
    ) -> Option<brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit> {
        family_positive_stop_probe::fired_limit()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for GoFamilyPositiveStopProbe {
    fn drop(&mut self) {
        let consumed = family_positive_stop_probe::clear();
        if !std::thread::panicking() {
            assert!(consumed, "family positive stop probe was not consumed");
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_go_forward_scan_probe_for_test() -> (usize, usize) {
    forward_scan_probe::take()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn stop_next_go_forward_scan_for_test() {
    forward_scan_probe::stop_next();
}

fn open() -> HierarchyAnswer {
    HierarchyAnswer {
        open: vec![HierarchyOpenReason::DescendantIndexUnavailable],
        ..Default::default()
    }
}
fn stopped() -> HierarchyAnswer {
    HierarchyAnswer {
        open: vec![HierarchyOpenReason::MemberFamily(
            MemberFamilyReason::HierarchyTruncated,
        )],
        ..Default::default()
    }
}
fn copy_answer(a: &HierarchyAnswer) -> HierarchyAnswer {
    HierarchyAnswer {
        edges: a.edges.clone(),
        ambiguous: a.ambiguous.clone(),
        open: a.open.clone(),
    }
}
fn classified(session: &ResolutionSession, token: &CancellationToken) -> HierarchyAnswer {
    match session.finish(()) {
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => stopped(),
        BoundedResolution::Complete { .. } if token.is_cancelled() => stopped(),
        BoundedResolution::Complete { .. } | BoundedResolution::Unavailable { .. } => open(),
    }
}

struct NativeQuery<'a, 'store, 'input> {
    go: &'a GoAnalyzer,
    operation: SelectedResolutionOperation<'store, 'input>,
    base: [u8; 32],
    token: CancellationToken,
    sessions: HashMap<i64, ResolutionSession>,
    ancestors: HashMap<CodeUnit, (HierarchyAnswer, QueryReadReceipt)>,
    forward_scans: HashMap<(i64, String), (GoForwardEmptyInterfaceScan, QueryReadReceipt)>,
}
impl NativeQuery<'_, '_, '_> {
    fn read(&mut self, unit: &CodeUnit, reverse: bool) -> Result<HierarchyAnswer> {
        if self.token.is_cancelled() {
            return Ok(stopped());
        }
        if reverse {
            self.go
                .inner
                .record_read(self.go.inner.workspace_scope_read_key(&[Language::Go]));
        }
        let path = brokk_bifrost_core::path_utils::rel_path_string(unit.source());
        let contexts = self.operation.go_contexts_for_file(&self.base, &path)?;
        if self.token.is_cancelled() {
            return Ok(stopped());
        }
        if contexts.is_empty() {
            return Ok(open());
        }
        let Some(mount) = self.operation.mount_table().mount_for_path("go", &path)? else {
            return Ok(open());
        };
        let mut answer = HierarchyAnswer::default();
        for (context, _) in contexts {
            if self.token.is_cancelled() {
                answer.merge(stopped());
                break;
            }
            let session = self.sessions.entry(context.context_id).or_insert_with(|| {
                ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&self.token))
            });
            let Some(role) = self.operation.go_source_role_for_mount(
                context.context_id,
                mount.ordinal(),
                &self.token,
            )?
            else {
                answer.merge(classified(session, &self.token));
                continue;
            };
            let definition =
                match self
                    .operation
                    .go_hierarchy_definition_match(unit, &self.token, session)?
                {
                    GoHierarchyDefinitionMatch::Found(id) => id,
                    GoHierarchyDefinitionMatch::Stopped { .. } => {
                        answer.merge(stopped());
                        continue;
                    }
                    GoHierarchyDefinitionMatch::Missing
                    | GoHierarchyDefinitionMatch::Ambiguous(_)
                    | GoHierarchyDefinitionMatch::Unavailable => {
                        answer.merge(open());
                        continue;
                    }
                };
            if reverse {
                let raw = self.operation.go_direct_subtypes(
                    context.context_id,
                    &role,
                    definition,
                    &self.token,
                    session,
                )?;
                if !raw.is_complete() {
                    answer.merge(classified(session, &self.token));
                }
                let mut ids = raw.edges.clone();
                ids.extend(raw.ambiguous.iter().copied());
                let units =
                    Self::hydrate(&self.operation, &self.token, &ids, session, &mut answer)?;
                for id in raw.edges {
                    if let Some(unit) = units.get(&id) {
                        answer.edges.push(unit.clone());
                    } else {
                        answer.merge(open());
                    }
                }
                for id in raw.ambiguous {
                    if let Some(unit) = units.get(&id) {
                        answer.ambiguous.push(vec![unit.clone()]);
                    } else {
                        answer.merge(open());
                    }
                }
                if !raw.open.is_empty() {
                    answer.merge(open());
                }
            } else {
                let scan_key = (context.context_id, role.clone());
                if let Some((_, receipt)) = self.forward_scans.get(&scan_key) {
                    receipt.replay(self.go);
                    if !session.observe_cancellation() || self.token.is_cancelled() {
                        answer.merge(stopped());
                        continue;
                    }
                } else {
                    #[cfg(any(test, feature = "test-support"))]
                    forward_scan_probe::scanned(session);
                    let (scan, receipt) = QueryReadReceipt::capture(self.go, || {
                        // The selected universe and its absence/coverage, placement,
                        // publication, version, recovery, and inventory predicates
                        // have no replayable read key. Keep the walk receipt honest.
                        self.go.inner.record_unattributed_read();
                        self.operation.go_forward_empty_interface_scan(
                            context.context_id,
                            &role,
                            &self.token,
                            session,
                        )
                    });
                    let scan = scan?;
                    if scan.is_complete()
                        && session.observe_cancellation()
                        && !self.token.is_cancelled()
                    {
                        self.forward_scans.insert(scan_key.clone(), (scan, receipt));
                        #[cfg(any(test, feature = "test-support"))]
                        forward_scan_probe::inserted();
                    } else {
                        // A partial scan cannot be reused as a negative. It is
                        // still valid evidence for this root's open answer.
                        let raw = self.operation.go_direct_supertypes_with_scan(
                            context.context_id,
                            &role,
                            definition,
                            &scan,
                            &self.token,
                            session,
                        )?;
                        Self::merge_supertype_answer(
                            &self.operation,
                            &self.token,
                            &mut answer,
                            raw,
                            session,
                        )?;
                        continue;
                    }
                }
                let scan = &self
                    .forward_scans
                    .get(&scan_key)
                    .expect("completed scan was inserted")
                    .0;
                let raw = self.operation.go_direct_supertypes_with_scan(
                    context.context_id,
                    &role,
                    definition,
                    scan,
                    &self.token,
                    session,
                )?;
                Self::merge_supertype_answer(
                    &self.operation,
                    &self.token,
                    &mut answer,
                    raw,
                    session,
                )?;
            }
        }
        answer.edges.sort();
        answer.edges.dedup();
        Ok(answer)
    }
    fn merge_supertype_answer(
        operation: &SelectedResolutionOperation<'_, '_>,
        token: &CancellationToken,
        answer: &mut HierarchyAnswer,
        raw: brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoDirectSupertypeAnswer,
        session: &ResolutionSession,
    ) -> Result<()> {
        if !raw.embeddings_complete() {
            answer.merge(classified(session, token));
        }
        if !raw.forward_satisfaction_enumerated {
            let classification = classified(session, token);
            if classification.open.iter().any(|reason| {
                matches!(
                    reason,
                    HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                )
            }) {
                if !answer.open.iter().any(|reason| {
                    matches!(
                        reason,
                        HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                    )
                }) {
                    answer.merge(classification);
                }
            } else {
                answer
                    .open
                    .push(HierarchyOpenReason::ForwardSatisfactionIncomplete);
            }
        }
        for parent in raw.parents {
            if parent.completion
                != brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete
                || parent.open_reason.is_some()
            {
                answer.merge(open());
            }
            let units = Self::hydrate(operation, token, &parent.targets, session, answer)?;
            let mut group = Vec::new();
            for id in &parent.targets {
                if let Some(unit) = units.get(id) {
                    group.push(unit.clone());
                } else {
                    answer.merge(open());
                }
            }
            if parent.targets.len() == 1
                && group.len() == 1
                && parent.completion
                    == brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete
                && parent.open_reason.is_none()
            {
                answer.edges.extend(group);
            } else if !group.is_empty() {
                answer.ambiguous.push(group);
            }
        }
        Ok(())
    }
    fn hydrate(
        operation: &SelectedResolutionOperation<'_, '_>,
        token: &CancellationToken,
        ids: &[brokk_bifrost_analysis::analyzer::resolution::SemanticId],
        session: &ResolutionSession,
        answer: &mut HierarchyAnswer,
    ) -> Result<HashMap<brokk_bifrost_analysis::analyzer::resolution::SemanticId, CodeUnit>> {
        let mut units = HashMap::new();
        for id in ids {
            let result = operation.go_hierarchy_definition_units(&[*id], token, session)?;
            let rows = match result {
                GoHierarchyHydration::Complete(rows) => rows,
                GoHierarchyHydration::Stopped(rows) => {
                    answer.merge(stopped());
                    rows
                }
                GoHierarchyHydration::Unavailable(rows) => {
                    answer.merge(open());
                    rows
                }
            };
            for (id, value) in rows {
                if let SelectedNativeDefinition::Unit(unit) = value {
                    units.insert(id, unit);
                } else {
                    answer.merge(open());
                }
            }
            if !session.observe_cancellation() {
                answer.merge(stopped());
                break;
            }
        }
        Ok(units)
    }
}
impl HierarchyQuery for NativeQuery<'_, '_, '_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        if self.token.is_cancelled() {
            return stopped();
        }
        if let Some((answer, receipt)) = self.ancestors.get(unit) {
            receipt.replay(self.go);
            return copy_answer(answer);
        }
        let (answer, receipt) = QueryReadReceipt::capture(self.go, || {
            self.read(unit, false).unwrap_or_else(|error| {
                self.go.inner.record_query_failure(error);
                stopped()
            })
        });
        self.ancestors
            .insert(unit.clone(), (copy_answer(&answer), receipt));
        answer
    }
    fn direct_descendants(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        self.read(unit, true).unwrap_or_else(|error| {
            self.go.inner.record_query_failure(error);
            open()
        })
    }
    fn direct_descendants_within(
        &mut self,
        unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> std::result::Result<HierarchyAnswer, Cancelled> {
        scope_filter_descendant_answer(self.direct_descendants(unit), scope)
    }
    fn member_family_ancestors(&mut self, unit: &CodeUnit) -> MemberFamilyAncestors {
        let answer = self.direct_ancestors(unit);
        MemberFamilyAncestors {
            resolved: answer.edges,
            ambiguous: answer.ambiguous,
            unread: Vec::new(),
        }
    }
}

enum OpenFailure {
    Store(StoreError),
    Cancelled,
    Stale(SelectedResolutionStale),
    Unavailable(SelectedResolutionUnavailable),
}

impl From<StoreError> for OpenFailure {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl OpenFailure {
    fn record(self, go: &GoAnalyzer) {
        let error = match self {
            Self::Store(error) => error,
            Self::Cancelled => {
                go.inner
                    .record_query_incomplete(QueryReadIncomplete::Cancelled);
                return;
            }
            Self::Stale(reason) => {
                StoreError::new(format!("Go hierarchy operation stale: {reason:?}"))
            }
            Self::Unavailable(reason) => {
                StoreError::new(format!("Go hierarchy operation unavailable: {reason:?}"))
            }
        };
        go.inner.record_query_failure(error);
    }

    fn family_reason(&self) -> MemberFamilyReason {
        match self {
            Self::Cancelled => MemberFamilyReason::HierarchyTruncated,
            Self::Store(_) => MemberFamilyReason::ProviderUnavailable,
            Self::Stale(_) | Self::Unavailable(_) => MemberFamilyReason::CoverageIncomplete,
        }
    }

    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

fn with_open_query<T>(
    go: &GoAnalyzer,
    cancellation: Option<&CancellationToken>,
    run: impl FnOnce(&mut NativeQuery<'_, '_, '_>) -> T,
) -> std::result::Result<T, OpenFailure> {
    let _model_scope = match AnalyzerQueryScope::pin_selected_model_snapshot(go) {
        Ok(scope) => scope,
        Err(_) => {
            go.inner.mark_execution_dependent();
            return Err(OpenFailure::Stale(
                SelectedResolutionStale::NativeContextPublication {
                    storage_language: "go".into(),
                },
            ));
        }
    };
    let token = cancellation
        .cloned()
        .or_else(|| go.inner.active_query_cancellation())
        .unwrap_or_default();
    (|| -> std::result::Result<T, OpenFailure> {
        let snapshots = go.inner.selected_workspace_snapshots();
        if !snapshots.contains_key("go") {
            return Err(StoreError::new("Go snapshot unavailable").into());
        }
        let Some(base) = go.native_context_base_profile() else {
            return Err(StoreError::new("Go base profile unavailable").into());
        };
        let (masks, content_mounts) = match go
            .inner
            .selected_resolution_overlay_inputs(snapshots.as_ref(), &token)?
        {
            SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } => (masks, content_mounts),
            SelectedResolutionOverlayInputsOutcome::Cancelled => {
                return Err(OpenFailure::Cancelled);
            }
            SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                return Err(OpenFailure::Stale(reason));
            }
            SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                return Err(OpenFailure::Unavailable(reason));
            }
        };
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let services =
            brokk_bifrost_analysis::analyzer::selected_services::AnalyzerSelectedServices(go);
        let input = SelectedResolutionOperationInput::new(
            go.inner.project(),
            go.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts)
        .with_analyzer(&services)
        .with_model_authority(super::selected_go_model_overlay(go).map(|overlay| overlay as std::sync::Arc<dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedModelAuthority + Send + Sync>));
        let operation = match go
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(input, &token)?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Err(OpenFailure::Cancelled);
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Err(OpenFailure::Stale(reason));
            }
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Err(OpenFailure::Unavailable(reason));
            }
        };
        let mut query = NativeQuery {
            go,
            operation: *operation,
            base,
            token,
            sessions: HashMap::new(),
            ancestors: HashMap::new(),
            forward_scans: HashMap::new(),
        };
        query.operation.initialize_go_base_profile(&base);
        Ok(run(&mut query))
    })()
}

pub(super) fn with_native_query(
    go: &GoAnalyzer,
    _root: Option<&CodeUnit>,
    run: &mut dyn FnMut(&mut dyn HierarchyQuery),
) {
    let result = with_open_query(go, None, |query| run(query));
    if let Err(error) = result {
        let mut fallback = Fallback {
            cancelled: error.is_cancelled(),
        };
        error.record(go);
        run(&mut fallback);
    }
}
struct Fallback {
    cancelled: bool,
}
impl HierarchyQuery for Fallback {
    fn direct_ancestors(&mut self, _: &CodeUnit) -> HierarchyAnswer {
        if self.cancelled { stopped() } else { open() }
    }
    fn direct_descendants(&mut self, _: &CodeUnit) -> HierarchyAnswer {
        if self.cancelled { stopped() } else { open() }
    }
    fn member_family_ancestors(&mut self, _: &CodeUnit) -> MemberFamilyAncestors {
        MemberFamilyAncestors::default()
    }
}
pub(super) fn supports(go: &GoAnalyzer, unit: &CodeUnit) -> bool {
    let result = with_open_query(go, None, |query| -> Result<bool> {
        let path = brokk_bifrost_core::path_utils::rel_path_string(unit.source());
        let Some(mount) = query.operation.mount_table().mount_for_path("go", &path)? else {
            return Ok(true);
        };
        let contexts = query.operation.go_contexts_for_file(&query.base, &path)?;
        if contexts.is_empty() {
            return Ok(true);
        }
        for (context, _) in contexts {
            let session = query.sessions.entry(context.context_id).or_insert_with(|| {
                ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&query.token))
            });
            let Some(role) = query.operation.go_source_role_for_mount(
                context.context_id,
                mount.ordinal(),
                &query.token,
            )?
            else {
                return Ok(true);
            };
            let GoHierarchyDefinitionMatch::Found(id) = query
                .operation
                .go_hierarchy_definition_match(unit, &query.token, session)?
            else {
                return Ok(true);
            };
            if query.operation.go_type_supports(context.context_id, &role, id, &query.token)? != brokk_bifrost_analysis::analyzer::store::resolution_operation::go_hierarchy::GoTypeSupport::Unsupported { return Ok(true); }
        }
        Ok(false)
    });
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            go.inner.record_query_failure(error);
            true
        }
        Err(error) => {
            error.record(go);
            true
        }
    }
}

#[derive(Default)]
struct FamilyDirection {
    edges: Vec<(CodeUnit, CodeUnit)>,
    reason: Option<MemberFamilyReason>,
}

impl FamilyDirection {
    fn mark(&mut self, reason: MemberFamilyReason) {
        fn priority(reason: MemberFamilyReason) -> u8 {
            match reason {
                MemberFamilyReason::HierarchyTruncated => 3,
                MemberFamilyReason::HierarchyAmbiguous => 2,
                MemberFamilyReason::ProviderUnavailable => 1,
                _ => 0,
            }
        }
        if self
            .reason
            .is_none_or(|old| priority(reason) > priority(old))
        {
            self.reason = Some(reason);
        }
    }

    fn completeness(&self) -> MemberFamilyCompleteness {
        MemberFamilyCompleteness {
            outcome: if self.reason.is_some() {
                MemberFamilyOutcome::Incomplete
            } else {
                MemberFamilyOutcome::Proven
            },
            reason: self.reason,
        }
    }
}

fn family_gap(session: &ResolutionSession, token: &CancellationToken) -> MemberFamilyReason {
    match session.finish(()) {
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
            MemberFamilyReason::HierarchyTruncated
        }
        BoundedResolution::Complete { .. } if token.is_cancelled() => {
            MemberFamilyReason::HierarchyTruncated
        }
        BoundedResolution::Complete { .. } | BoundedResolution::Unavailable { .. } => {
            MemberFamilyReason::CoverageIncomplete
        }
    }
}

fn family_provider_gap(
    session: &ResolutionSession,
    token: &CancellationToken,
) -> MemberFamilyReason {
    match family_gap(session, token) {
        MemberFamilyReason::HierarchyTruncated => MemberFamilyReason::HierarchyTruncated,
        _ => MemberFamilyReason::ProviderUnavailable,
    }
}

fn hydrate_family_direction(
    operation: &SelectedResolutionOperation<'_, '_>,
    go: &GoAnalyzer,
    token: &CancellationToken,
    ids: &[brokk_bifrost_analysis::analyzer::resolution::SemanticId],
    session: &ResolutionSession,
    direction: &mut FamilyDirection,
    #[cfg(any(test, feature = "test-support"))] inverse: bool,
) -> Result<()> {
    for id in ids {
        let rows = match operation.go_hierarchy_definition_units(&[*id], token, session)? {
            GoHierarchyHydration::Complete(rows) => rows,
            GoHierarchyHydration::Stopped(rows) => {
                direction.mark(MemberFamilyReason::HierarchyTruncated);
                rows
            }
            GoHierarchyHydration::Unavailable(rows) => {
                go.inner
                    .record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                        "Go hierarchy method hydration unavailable".into(),
                    ));
                direction.mark(family_provider_gap(session, token));
                rows
            }
        };
        let mut units = rows.into_iter().filter_map(|(found, value)| {
            (found == *id)
                .then_some(value)
                .and_then(|value| match value {
                    SelectedNativeDefinition::Unit(unit) => Some(unit),
                    _ => None,
                })
        });
        let Some(unit) = units.next() else {
            direction.mark(family_gap(session, token));
            continue;
        };
        if units.next().is_some() {
            direction.mark(MemberFamilyReason::HierarchyAmbiguous);
            continue;
        }
        let Some(owner) = go.inner.parent_of(&unit).filter(CodeUnit::is_class) else {
            direction.mark(MemberFamilyReason::CoverageIncomplete);
            continue;
        };
        direction.edges.push((unit, owner));
        #[cfg(any(test, feature = "test-support"))]
        family_positive_stop_probe::after_positive(inverse, session);
    }
    if matches!(
        session.finish(()),
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. }
    ) {
        direction.mark(MemberFamilyReason::HierarchyTruncated);
    }
    Ok(())
}

fn read_member_family(
    query: &mut NativeQuery<'_, '_, '_>,
    member: &CodeUnit,
) -> Result<MemberFamilyAnswer> {
    let capability = super::go_member_family_capability(member);
    // The selected coverage key does not certify role or outcome, including
    // an empty context discovery. Capture this crossing with the call.
    query.go.inner.record_unattributed_read();
    if query.token.is_cancelled() {
        return Ok(MemberFamilyAnswer::incomplete(
            capability,
            MemberFamilyReason::HierarchyTruncated,
        ));
    }
    let path = brokk_bifrost_core::path_utils::rel_path_string(member.source());
    let contexts = query.operation.go_contexts_for_file(&query.base, &path)?;
    if query.token.is_cancelled() {
        return Ok(MemberFamilyAnswer::incomplete(
            capability,
            MemberFamilyReason::HierarchyTruncated,
        ));
    }
    let Some(mount) = query.operation.mount_table().mount_for_path("go", &path)? else {
        return Ok(MemberFamilyAnswer::incomplete(
            capability,
            MemberFamilyReason::CoverageIncomplete,
        ));
    };
    let mut forward = FamilyDirection::default();
    let mut inverse = FamilyDirection::default();
    if contexts.is_empty() {
        forward.mark(MemberFamilyReason::CoverageIncomplete);
        inverse.mark(MemberFamilyReason::CoverageIncomplete);
    }
    for (context, _) in contexts {
        let session = query.sessions.entry(context.context_id).or_insert_with(|| {
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&query.token))
        });
        if !session.observe_cancellation() {
            forward.mark(MemberFamilyReason::HierarchyTruncated);
            inverse.mark(MemberFamilyReason::HierarchyTruncated);
            break;
        }
        let role = match query.operation.go_source_role_for_mount(
            context.context_id,
            mount.ordinal(),
            &query.token,
        ) {
            Ok(role) => role,
            Err(error) => {
                record_family_store_failure(query.go, error);
                let reason = family_provider_gap(session, &query.token);
                forward.mark(reason);
                inverse.mark(reason);
                continue;
            }
        };
        let Some(role) = role else {
            let reason = family_gap(session, &query.token);
            forward.mark(reason);
            inverse.mark(reason);
            continue;
        };
        let id = match query
            .operation
            .go_hierarchy_definition_match(member, &query.token, session)
        {
            Ok(result) => match result {
                GoHierarchyDefinitionMatch::Found(id) => id,
                GoHierarchyDefinitionMatch::Ambiguous(_) => {
                    forward.mark(MemberFamilyReason::HierarchyAmbiguous);
                    inverse.mark(MemberFamilyReason::HierarchyAmbiguous);
                    continue;
                }
                GoHierarchyDefinitionMatch::Stopped { .. } => {
                    forward.mark(MemberFamilyReason::HierarchyTruncated);
                    inverse.mark(MemberFamilyReason::HierarchyTruncated);
                    continue;
                }
                GoHierarchyDefinitionMatch::Missing => {
                    let reason = family_gap(session, &query.token);
                    forward.mark(reason);
                    inverse.mark(reason);
                    continue;
                }
                GoHierarchyDefinitionMatch::Unavailable => {
                    query.go.inner.record_query_incomplete(
                        QueryReadIncomplete::SemanticEvidenceUnavailable(
                            "Go hierarchy method crosswalk unavailable".into(),
                        ),
                    );
                    let reason = family_provider_gap(session, &query.token);
                    forward.mark(reason);
                    inverse.mark(reason);
                    continue;
                }
            },
            Err(error) => {
                record_family_store_failure(query.go, error);
                let reason = family_provider_gap(session, &query.token);
                forward.mark(reason);
                inverse.mark(reason);
                continue;
            }
        };
        // The coverage key names selection and context, but not the role or
        // outcome whose completeness this family call uses.
        let raw = match query.operation.go_native_method_family(
            context.context_id,
            &role,
            id,
            &query.token,
            session,
        ) {
            Ok(raw) => raw,
            Err(error) => {
                record_family_store_failure(query.go, error);
                let reason = family_provider_gap(session, &query.token);
                forward.mark(reason);
                inverse.mark(reason);
                continue;
            }
        };
        if !raw.implements.is_complete() {
            forward.mark(family_gap(session, &query.token));
        }
        if !raw.implemented_by.is_complete() {
            inverse.mark(family_gap(session, &query.token));
        }
        if let Err(error) = hydrate_family_direction(
            &query.operation,
            query.go,
            &query.token,
            &raw.implements.methods,
            session,
            &mut forward,
            #[cfg(any(test, feature = "test-support"))]
            false,
        ) {
            record_family_store_failure(query.go, error);
            forward.mark(family_provider_gap(session, &query.token));
        }
        if let Err(error) = hydrate_family_direction(
            &query.operation,
            query.go,
            &query.token,
            &raw.implemented_by.methods,
            session,
            &mut inverse,
            #[cfg(any(test, feature = "test-support"))]
            true,
        ) {
            record_family_store_failure(query.go, error);
            inverse.mark(family_provider_gap(session, &query.token));
        }
        let scan_key = (context.context_id, role.clone());
        if let Some((scan, receipt)) = query.forward_scans.get(&scan_key) {
            receipt.replay(query.go);
            if scan.has_open_reasons() {
                forward.mark(family_gap(session, &query.token));
            }
        } else {
            let (scan, receipt) = QueryReadReceipt::capture(query.go, || {
                query.go.inner.record_unattributed_read();
                query.operation.go_forward_empty_interface_scan(
                    context.context_id,
                    &role,
                    &query.token,
                    session,
                )
            });
            match scan {
                Ok(scan) => {
                    if scan.has_open_reasons() {
                        forward.mark(family_gap(session, &query.token));
                    }
                    if scan.is_complete()
                        && session.observe_cancellation()
                        && !query.token.is_cancelled()
                    {
                        query.forward_scans.insert(scan_key, (scan, receipt));
                    }
                }
                Err(error) => {
                    record_family_store_failure(query.go, error);
                    forward.mark(family_provider_gap(session, &query.token));
                }
            }
        }
        if !session.observe_cancellation() || query.token.is_cancelled() {
            forward.mark(MemberFamilyReason::HierarchyTruncated);
        }
    }
    Ok(assemble_member_family(capability, member, forward, inverse))
}

fn assemble_member_family(
    capability: MemberFamilyCapability,
    member: &CodeUnit,
    mut forward: FamilyDirection,
    mut inverse: FamilyDirection,
) -> MemberFamilyAnswer {
    forward.edges.sort();
    forward.edges.dedup();
    inverse.edges.sort();
    inverse.edges.dedup();
    let forward_quality = forward.completeness();
    let inverse_quality = inverse.completeness();
    let forward_closed = forward.reason.is_none();
    let mut answer =
        brokk_bifrost_analysis::analyzer::usages::member_family::proven_member_family_answer(
            capability,
            member,
            forward.edges,
            inverse.edges,
        );
    answer.ancestors = forward_quality;
    answer.descendants = inverse_quality;
    answer.reason = match (forward.reason, inverse.reason) {
        (Some(MemberFamilyReason::HierarchyTruncated), _)
        | (_, Some(MemberFamilyReason::HierarchyTruncated)) => {
            Some(MemberFamilyReason::HierarchyTruncated)
        }
        (Some(MemberFamilyReason::HierarchyAmbiguous), _)
        | (_, Some(MemberFamilyReason::HierarchyAmbiguous)) => {
            Some(MemberFamilyReason::HierarchyAmbiguous)
        }
        (Some(reason), _) | (_, Some(reason)) => Some(reason),
        (None, None) => None,
    };
    if answer.reason.is_some() {
        answer.outcome = MemberFamilyOutcome::Incomplete;
        if !forward_closed {
            answer.roots.clear();
        }
    }
    answer
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assemble_go_member_family_for_test(
    capability: MemberFamilyCapability,
    member: &CodeUnit,
    forward_edges: Vec<(CodeUnit, CodeUnit)>,
    forward_reason: Option<MemberFamilyReason>,
    inverse_edges: Vec<(CodeUnit, CodeUnit)>,
    inverse_reason: Option<MemberFamilyReason>,
) -> MemberFamilyAnswer {
    assemble_member_family(
        capability,
        member,
        FamilyDirection {
            edges: forward_edges,
            reason: forward_reason,
        },
        FamilyDirection {
            edges: inverse_edges,
            reason: inverse_reason,
        },
    )
}

fn record_family_store_failure(go: &GoAnalyzer, error: StoreError) {
    go.inner
        .record_query_incomplete(QueryReadIncomplete::StoreFailure(error.clone()));
    go.inner.record_query_failure(error);
}

pub(super) fn member_family(
    go: &GoAnalyzer,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    if std::env::var_os("G2_WITNESS_TRACE").is_some() {
        eprintln!("G2_WITNESS_ROUTE member_family {}", member.fq_name());
    }
    let capability = super::go_member_family_capability(member);
    let token = cancellation
        .cloned()
        .or_else(|| go.inner.active_query_cancellation())
        .unwrap_or_default();
    if capability == MemberFamilyCapability::Unsupported {
        return MemberFamilyAnswer::unsupported_answer();
    }
    if token.is_cancelled() {
        return MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::HierarchyTruncated);
    }
    if !member.is_function() {
        return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
    }
    // A package-level function has no receiver family. Other function-shaped
    // projections still need the selected store's authority to decide Open.
    if member.declaration_segment_count() == 1 {
        return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
    }
    let (answer, _receipt) = QueryReadReceipt::capture(go, || {
        match with_open_query(go, Some(&token), |query| read_member_family(query, member)) {
            Ok(Ok(answer)) => answer,
            Ok(Err(error)) => {
                go.inner
                    .record_query_incomplete(QueryReadIncomplete::StoreFailure(error.clone()));
                go.inner.record_query_failure(error);
                MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::ProviderUnavailable)
            }
            Err(error) => {
                let reason = error.family_reason();
                error.record(go);
                MemberFamilyAnswer::incomplete(capability, reason)
            }
        }
    });
    answer
}
