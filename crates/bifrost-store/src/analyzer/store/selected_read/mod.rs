//! Recorded SQL capabilities for one immutable selected inventory.
use super::resolution_operation::{ReadySelectedResolution, SelectedAnalyzerServices};
use super::resolution_selection::SelectedResolutionMountInventory;
use super::selected_read_memo::{ExactReadByteBudget, ExactReadMemo};
use super::{StoreError, WorkspaceSnapshotId};
use crate::analyzer::Language;
use brokk_bifrost_core::gitblob::ParseVariant;
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    DerivationAuthority, DerivationFrame, DerivationKindId, DerivationRevision,
};
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
    LookupQuestion, WorkspaceFactFamily,
};
use rusqlite::Connection;
use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::hash::Hash;
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod registry;
pub mod relations;
pub type SelectedReadError = StoreError;

type CapturedReceipt = Arc<dyn Any + Send + Sync>;
#[derive(Clone)]
enum Receipt {
    Captured(CapturedReceipt),
    Refused,
}

type ReadEpoch = (u64, u64, [u8; 32], (u64, u64));

/// One first dependency makes an empty selection declaration unrepresentable.
pub struct NonEmpty<T> {
    pub first: T,
    pub rest: Vec<T>,
}
impl<T> NonEmpty<T> {
    pub fn one(first: T) -> Self {
        Self {
            first,
            rest: Vec::new(),
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

#[derive(Clone, Debug)]
pub enum SelectedDependency {
    Path {
        language: Language,
        rel_path: Box<str>,
        selected: Option<(git2::Oid, ParseVariant)>,
    },
    Scope {
        languages: Box<[Language]>,
    },
    WorkspaceFact {
        family: WorkspaceFactFamily,
        question: Box<LookupQuestion>,
        snapshot: WorkspaceSnapshotId,
        base_profile: [u8; 32],
    },
    /// A workspace fact whose digest the store already computed over the exact
    /// rows the query read. The recorded key is `Lookup WorkspaceFact` with
    /// that digest; verification asks the owning analyzer for the head digest,
    /// computed by the same store function (#13276).
    WorkspaceFactDigest {
        question: Box<LookupQuestion>,
        digest: brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest,
    },
}

/// The analysis layer retains the complete ledger, including refusal channels.
pub trait SelectedReadRecording {
    fn capture(
        &self,
        work: &mut dyn FnMut() -> Result<(), SelectedReadError>,
    ) -> (Result<(), SelectedReadError>, CapturedReceipt);
    fn replay(&self, receipt: &(dyn Any + Send + Sync));
    fn reusable(&self, receipt: &(dyn Any + Send + Sync)) -> bool;
    fn receipt_bytes(&self, receipt: &(dyn Any + Send + Sync)) -> usize;
    fn failed(&self, error: &SelectedReadError, cancelled: bool);
    fn matches_frame(
        &self,
        owner: DerivationKindId,
        revision: &dyn Any,
        authority: &dyn Any,
        inventory: &SelectedResolutionMountInventory<'_>,
    ) -> bool;
}
#[derive(Clone, Copy)]
pub struct SelectedReadRecorder<'a> {
    recording: &'a dyn SelectedReadRecording,
}
impl<'a> SelectedReadRecorder<'a> {
    pub fn new(recording: &'a dyn SelectedReadRecording) -> Self {
        Self { recording }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct InventoryIdentity {
    store: usize,
    request: u64,
}

/// A selected content identity and the receipt that selected it. No public mint.
#[derive(Clone)]
pub struct RecordedContent {
    identity: InventoryIdentity,
    mount: MountContent,
    receipt: Receipt,
    receipt_bytes: usize,
}
impl std::fmt::Debug for RecordedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedContent")
            .field("identity", &self.identity)
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}
impl PartialEq for RecordedContent {
    fn eq(&self, rhs: &Self) -> bool {
        self.identity == rhs.identity && self.mount == rhs.mount
    }
}
impl Eq for RecordedContent {}
impl Hash for RecordedContent {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.identity.hash(h);
        self.mount.hash(h);
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MountContent {
    blob_id: i64,
    language: Language,
    path: Box<str>,
    oid: git2::Oid,
    variant: ParseVariant,
}
pub trait HasRecordedContent {
    fn recorded_content(&self) -> &RecordedContent;
}
impl HasRecordedContent for RecordedContent {
    fn recorded_content(&self) -> &RecordedContent {
        self
    }
}

mod sealed {
    use super::*;
    pub struct ExecutionAccess(());
    pub(super) fn execution_access() -> ExecutionAccess {
        ExecutionAccess(())
    }
    pub trait Query: 'static {
        type Params: Clone + Eq + Hash + 'static;
        type Answer: Clone + 'static;
        const SQL: &'static str;
        const COVERAGE: brokk_bifrost_core::attribution::CoverageClass;
        fn read(
            _access: &ExecutionAccess,
            statement: &mut rusqlite::Statement<'_>,
            params: &Self::Params,
        ) -> Result<Self::Answer, SelectedReadError>;
        fn answer_bytes(answer: &Self::Answer) -> usize;
        fn params_bytes(params: &Self::Params) -> usize;
    }
}
pub trait ContentQuery: sealed::Query
where
    Self::Params: HasRecordedContent,
{
}
pub trait SelectionQuery: sealed::Query {
    fn dependencies(params: &Self::Params, answer: &Self::Answer) -> NonEmpty<SelectedDependency>;
}
pub trait DerivationInputQuery: sealed::Query {
    const OWNER: DerivationKindId;
}

macro_rules! selected_queries {
    ($( $(#[$meta:meta])* $role:ident $name:ident { params: $params:ty, answer: $answer:ty, sql: $sql:expr, read: $read:expr, bytes: $bytes:expr, params_bytes: $params_bytes:expr, contract: $contract:expr } )*) => {
        $( $(#[$meta])* pub struct $name;
        $(#[$meta])* impl $crate::analyzer::store::selected_read::sealed::Query for $name {
            type Params=$params; type Answer=$answer; const SQL:&'static str=$sql;
            const COVERAGE:brokk_bifrost_core::attribution::CoverageClass=selected_queries!(@coverage $role);
            fn read(_access:&super::super::sealed::ExecutionAccess,statement:&mut rusqlite::Statement<'_>,params:&Self::Params)->Result<Self::Answer,super::super::SelectedReadError> { ($read)(statement,params) }
            fn answer_bytes(answer:&Self::Answer)->usize { ($bytes)(answer) }
            fn params_bytes(params:&Self::Params)->usize { ($params_bytes)(params) }
        }
        $(#[$meta])* selected_queries!(@role $role $name, $contract);)*
        #[cfg(any(test, feature = "test-support"))]
        pub(in crate::analyzer::store::selected_read) const QUERIES:&[super::super::registry::QueryRegistration]=&[$( $(#[$meta])* super::super::registry::QueryRegistration { name:stringify!($name), sql:$sql, class:selected_queries!(@class $role), owner:selected_queries!(@owner $role $contract) },)*];
    };
    (@role selection $name:ident, $contract:expr) => { impl super::super::SelectionQuery for $name { fn dependencies(params:&Self::Params,answer:&Self::Answer)->super::super::NonEmpty<super::super::SelectedDependency> { ($contract)(params,answer) } } };
    (@role content $name:ident, $contract:expr) => { impl super::super::ContentQuery for $name {} };
    (@role derivation $name:ident, $contract:expr) => { impl super::super::DerivationInputQuery for $name { const OWNER:brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId=$contract; } };
    (@coverage derivation) => { brokk_bifrost_core::attribution::CoverageClass::RecomputeOnCurrency };
    (@coverage $other:ident) => { brokk_bifrost_core::attribution::CoverageClass::ExactKeys };
    (@class selection) => { super::super::registry::QueryClass::Selection };
    (@class content) => { super::super::registry::QueryClass::Content };
    (@class derivation) => { super::super::registry::QueryClass::DerivationInput };
    (@owner derivation $contract:expr) => { Some($contract) };
    (@owner $other:ident $contract:expr) => { None };
}

pub mod queries;

/// What a `SelectedRead` reads through: one immutable selected inventory.
pub trait SelectedInventory {
    fn selected_inventory(&self) -> &SelectedResolutionMountInventory<'_>;
}
impl SelectedInventory for SelectedResolutionMountInventory<'_> {
    fn selected_inventory(&self) -> &SelectedResolutionMountInventory<'_> {
        self
    }
}
impl SelectedInventory for ReadySelectedResolution<'_, '_> {
    fn selected_inventory(&self) -> &SelectedResolutionMountInventory<'_> {
        &self.inventory
    }
}

pub struct SelectedRead<'a> {
    connection: &'a Connection,
    inventory: &'a SelectedResolutionMountInventory<'a>,
    services: &'a dyn SelectedAnalyzerServices,
    recorder: Option<SelectedReadRecorder<'a>>,
    cancellation: crate::CancellationToken,
    memos: RefCell<crate::hash::HashMap<TypeId, Box<dyn Any>>>,
    budget: RefCell<ExactReadByteBudget>,
    identity: InventoryIdentity,
}
struct MemoValue<A> {
    answer: A,
    receipt: Receipt,
}
impl<A: Clone> Clone for MemoValue<A> {
    fn clone(&self) -> Self {
        Self {
            answer: self.answer.clone(),
            receipt: self.receipt.clone(),
        }
    }
}
impl<'a> SelectedRead<'a> {
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: SelectedRead owns selected SQL execution"
    )]
    pub fn new(
        selection: &'a impl SelectedInventory,
        services: &'a dyn SelectedAnalyzerServices,
    ) -> Self {
        let inventory = selection.selected_inventory();
        Self {
            connection: inventory.connection(),
            inventory,
            services,
            recorder: services.selected_read_recorder(),
            cancellation: inventory.selected_read_cancellation(),
            memos: RefCell::default(),
            budget: RefCell::default(),
            identity: InventoryIdentity {
                store: inventory.store_identity(),
                request: inventory.selected_read_request_identity(),
            },
        }
    }
    fn replay(&self, receipt: &Receipt) {
        match (receipt, self.recorder) {
            (Receipt::Captured(captured), Some(recorder)) => {
                recorder.recording.replay(captured.as_ref())
            }
            _ => self.services.refuse_read_reuse(),
        }
    }
    fn receipt_bytes(&self, receipt: &Receipt) -> usize {
        match (receipt, self.recorder) {
            (Receipt::Captured(captured), Some(recorder)) => {
                recorder.recording.receipt_bytes(captured.as_ref())
            }
            _ => 0,
        }
    }
    fn failed<T>(&self, error: SelectedReadError) -> Result<T, SelectedReadError> {
        self.services.refuse_read_reuse();
        self.services
            .selected_read_failed(&error, self.cancellation.is_cancelled());
        Err(error)
    }
    fn check(&self) -> Result<(), SelectedReadError> {
        if self.recorder.is_none() {
            self.services.refuse_read_reuse();
        }
        if self.cancellation.is_cancelled() {
            return self.failed(StoreError::new("selected read cancelled"));
        }
        Ok(())
    }
    fn execute<Q: sealed::Query>(
        &self,
        params: &Q::Params,
        record: impl FnOnce(&Q::Answer) -> Result<(), SelectedReadError>,
    ) -> Result<(Q::Answer, Receipt), SelectedReadError> {
        self.check()?;
        let key = (self.inventory.selected_read_epoch(), params.clone());
        let cached = {
            self
            .memos
            .borrow()
            .get(&TypeId::of::<Q>())
            .and_then(|memo| {
                memo.downcast_ref::<ExactReadMemo<(ReadEpoch, Q::Params), MemoValue<Q::Answer>>>()
            })
            .and_then(|memo| memo.get(&key))
            .cloned()
        };
        if let Some(value) = cached {
            self.replay(&value.receipt);
            return Ok((value.answer, value.receipt));
        }
        let mut answer = None;
        let mut record = Some(record);
        let mut work = || {
            let _coverage =
                brokk_bifrost_core::attribution::enter_scope("selected_read", Q::COVERAGE);
            let value = super::resolution::with_resolution_read_progress_handler(
                self.connection,
                &self.cancellation,
                |connection| {
                    let mut statement = connection.prepare_cached(Q::SQL)?;
                    if !statement.readonly() {
                        return Err(StoreError::new(
                            "registered selected query is not read-only",
                        ));
                    }
                    Q::read(&sealed::execution_access(), &mut statement, params)
                },
            )?;
            if self.cancellation.is_cancelled() {
                return Err(StoreError::new("selected read cancelled"));
            }
            record.take().expect("query recording runs once")(&value)?;
            answer = Some(value);
            Ok(())
        };
        let (result, receipt) = if let Some(recorder) = self.recorder {
            let (result, receipt) = recorder.recording.capture(&mut work);
            (result, Receipt::Captured(receipt))
        } else {
            (work(), Receipt::Refused)
        };
        if let Err(error) = result {
            return self.failed(error);
        }
        let answer = answer.expect("successful selected query decoded its answer");
        if let (Some(recorder), Receipt::Captured(captured)) = (self.recorder, &receipt) {
            let bytes = Q::params_bytes(params)
                .saturating_add(Q::answer_bytes(&answer))
                .saturating_add(recorder.recording.receipt_bytes(captured.as_ref()));
            if recorder.recording.reusable(captured.as_ref())
                && self.budget.borrow_mut().admit(bytes)
            {
                let mut memos = self.memos.borrow_mut();
                let memo = memos
                    .entry(TypeId::of::<Q>())
                    .or_insert_with(|| {
                        Box::new(
                            ExactReadMemo::<(ReadEpoch, Q::Params), MemoValue<Q::Answer>>::default(
                            ),
                        )
                    })
                    .downcast_mut::<ExactReadMemo<(ReadEpoch, Q::Params), MemoValue<Q::Answer>>>()
                    .expect("query TypeId owns its typed memo");
                if !memo.insert_bounded_weighed(
                    key,
                    MemoValue {
                        answer: answer.clone(),
                        receipt: receipt.clone(),
                    },
                    bytes,
                ) {
                    self.budget.borrow_mut().release(bytes);
                }
            }
        }
        Ok((answer, receipt))
    }
    pub fn selection<Q: SelectionQuery>(
        &self,
        params: &Q::Params,
    ) -> Result<Q::Answer, SelectedReadError> {
        self.execute::<Q>(params, |answer| {
            for dependency in Q::dependencies(params, answer).iter() {
                self.services.record_selected_dependency(dependency)?;
            }
            Ok(())
        })
        .map(|(answer, _)| answer)
    }
    pub fn content<Q: ContentQuery>(
        &self,
        params: &Q::Params,
    ) -> Result<Q::Answer, SelectedReadError>
    where
        Q::Params: HasRecordedContent,
    {
        self.check()?;
        let content = params.recorded_content();
        if content.identity != self.identity {
            return self.failed(StoreError::new(
                "content belongs to another selected inventory",
            ));
        }
        self.replay(&content.receipt);
        self.execute::<Q>(params, |_| {
            self.replay(&content.receipt);
            Ok(())
        })
        .map(|(answer, _)| answer)
    }
    pub fn derivation_input<
        Q: DerivationInputQuery,
        R: DerivationRevision,
        A: DerivationAuthority,
    >(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        params: &Q::Params,
    ) -> Result<Q::Answer, SelectedReadError> {
        let allowed = frame.authorizes_selected_input(Q::OWNER, |revision, authority| {
            self.recorder.is_some_and(|recorder| {
                recorder
                    .recording
                    .matches_frame(Q::OWNER, revision, authority, self.inventory)
            })
        });
        if !allowed {
            return self.failed(StoreError::new(
                "derivation input does not belong to this compute frame and inventory",
            ));
        }
        let result = self
            .execute::<Q>(params, |_| Ok(()))
            .map(|(answer, _)| answer);
        if result.is_err() {
            frame.selected_input_unavailable();
        }
        result
    }
    pub fn mount_by_path(
        &self,
        language: Language,
        path: &str,
    ) -> Result<Option<RecordedContent>, SelectedReadError> {
        let params = queries::common::MountPath {
            language,
            path: path.into(),
        };
        let (answer, receipt) =
            self.execute::<queries::common::MountByPath>(&params, |answer| {
                for dependency in queries::common::MountByPath::dependencies(&params, answer).iter()
                {
                    self.services.record_selected_dependency(dependency)?;
                }
                Ok(())
            })?;
        Ok(answer.map(|mount| RecordedContent {
            identity: self.identity,
            mount,
            receipt_bytes: self.receipt_bytes(&receipt),
            receipt,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::hooks::{AuthAction, Authorization};
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn selected_queries_read_only_relations_their_class_allows() {
        let store = super::super::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.read_conn().unwrap();
        super::super::ensure_revisioned_workspace_views(&connection).unwrap();
        connection
            .execute_batch(
                super::super::resolution_selection::selected_resolution_temp_schema_sql(),
            )
            .unwrap();
        connection
            .execute_batch(super::super::csharp_compilation::extent::OVERLAY_SCHEMA)
            .unwrap();
        connection.execute_batch("CREATE TEMP VIEW selected_read_authorizer_view AS SELECT blob_id FROM temp.selected_resolution_mounts").unwrap();
        let mut catalog = BTreeSet::new();
        for database in ["main", "temp"] {
            let names = connection
                .prepare(&format!(
                    "SELECT name FROM {database}.sqlite_schema WHERE type IN ('view','table')"
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for name in names {
                catalog.insert((database.to_owned(), name.clone()));
                assert!(
                    relations::class(database, &name).is_some(),
                    "unclassified schema relation {database}.{name}"
                );
            }
        }
        let mut observed = BTreeSet::new();
        for query in registry::queries() {
            connection.flush_prepared_statement_cache();
            let reads = Arc::new(Mutex::new(BTreeSet::new()));
            let capture = reads.clone();
            connection
                .authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
                    if let AuthAction::Read { table_name, .. } = context.action {
                        capture.lock().unwrap().insert((
                            context.database_name.unwrap_or("main").to_owned(),
                            table_name.to_owned(),
                        ));
                    }
                    Authorization::Allow
                }))
                .unwrap();
            let statement = connection
                .prepare(query.sql)
                .unwrap_or_else(|error| panic!("{} must prepare: {error}", query.name));
            assert!(statement.readonly(), "{} must be read-only", query.name);
            drop(statement);
            connection
                .authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>)
                .unwrap();
            for (database, relation) in reads.lock().unwrap().iter() {
                if !catalog.contains(&(database.clone(), relation.clone())) {
                    eprintln!(
                        "{}: skipped noncatalog CTE/subquery relation {database}.{relation}",
                        query.name
                    );
                    continue;
                }
                let class = relations::class(database, relation).unwrap_or_else(|| {
                    panic!("{} reads unclassified {database}.{relation}", query.name)
                });
                assert!(
                    query.class != registry::QueryClass::Content
                        || class == relations::RelationClass::Content,
                    "{} content query reads selection {database}.{relation}",
                    query.name
                );
                observed.insert((database.clone(), relation.clone()));
            }
            if query.class == registry::QueryClass::DerivationInput {
                assert!(
                    query.owner.is_some(),
                    "{} requires its registered recompute owner",
                    query.name
                );
                // Runtime frame admission also checks the engine's registered
                // verification mode, rather than trusting a query's label.
            }
        }
        assert!(observed.contains(&("main".to_owned(), "live_code_units".to_owned())));
        assert!(observed.contains(&(
            "temp".to_owned(),
            "selected_read_authorizer_view".to_owned()
        )));
        assert!(observed.contains(&("main".to_owned(), "blobs".to_owned())));
        assert!(observed.contains(&("temp".to_owned(), "selected_resolution_mounts".to_owned())));
    }
}
