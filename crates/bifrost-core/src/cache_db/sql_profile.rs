//! Per-statement SQLite profile for the analyzer store.
//!
//! The store has hundreds of `prepare` call sites and nothing that says which
//! of them actually run, how often, or what they cost. SQLite answers that
//! itself: `sqlite3_trace_v2` with `SQLITE_TRACE_PROFILE` calls back after every
//! statement finishes with the statement and its elapsed nanoseconds. This
//! module turns those callbacks into one bounded per-process aggregate and
//! writes it as JSON lines, so `scripts/sql-usefulness-ledger.py` can join the
//! statements to the tables and indexes they touch.
//!
//! The instrument is off unless `BIFROST_SQL_PROFILE` names an output file. The
//! variable is read once per process; with it unset, the profile collector
//! stays off while the statement-start attribution guard remains installed.
//!
//! One callback per connection dispatches attribution, profiling and listeners.
//!
//! Both JSONL outputs start with `profile_header`, format_version 2. In a
//! cumulative dump, the sum of statement, sqlite_internal_rows and overflow
//! decoded_rows equals the header decoded_rows and totals_with_rows.
//! This partitions ROW events by their own SQL, independently of completion.
//! Request records use the same partition in their statements and
//! sqlite_internal_rows arrays. For a non-overlapping request, their sum equals
//! the totals_with_rows delta over the scope (per role as well as overall).
//! In contrast, statement `rows` and row_histogram attribute nested internal ROW
//! events to the active application statement too. Do not add `rows` to the
//! decoded_rows partition: that would count those internal rows twice.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, c_void};
use std::fs::OpenOptions;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use crate::attribution::ConnectionTag;
use rusqlite::{Connection, ffi};

#[cfg(test)]
thread_local! { static ROW_DISPATCHES: Cell<usize> = const { Cell::new(0) }; }

type Listener = Arc<dyn for<'a> Fn(ListenerEvent<'a>) + Send + Sync>;
#[derive(Clone, Copy)]
pub enum ListenerEvent<'a> {
    Statement {
        statement: usize,
        sql: Option<&'a str>,
    },
    Row {
        statement: usize,
        sql: Option<&'a str>,
    },
    Profile {
        statement: usize,
        sql: Option<&'a str>,
        elapsed: Duration,
    },
}
struct TraceContext {
    tag: ConnectionTag,
    /// A `ConnectionRole` discriminant. Atomic because a reinstall on the
    /// owning thread updates it while a `ListenerGuard` on another thread may
    /// hold a shared reference to this context.
    role: std::sync::atomic::AtomicU8,
    db: *mut ffi::sqlite3,
    profiling: bool,
    listeners: Mutex<HashMap<u64, Listener>>,
    next_listener: std::sync::atomic::AtomicU64,
}
// A live registry entry always names a live connection: CLOSE removes it before
// SQLite frees that handle, so reuse of a sqlite3 address cannot match an old tag.
static TAGS: OnceLock<Mutex<HashMap<usize, ConnectionTag>>> = OnceLock::new();
fn tags() -> &'static Mutex<HashMap<usize, ConnectionTag>> {
    TAGS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn connection_tag(conn: &Connection) -> Option<ConnectionTag> {
    // SAFETY: a borrowed Connection keeps its sqlite3 handle live.
    tags()
        .lock()
        .expect("tag registry poisoned")
        .get(&(unsafe { conn.handle() } as usize))
        .copied()
}
pub struct ListenerGuard {
    tag: ConnectionTag,
    id: u64,
}
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        // SAFETY: CLOSE removes the context under this same registry lock
        // before freeing it. A concurrent drop either precedes that free or
        // sees no context. Tags are never reused.
        let registry = contexts().lock().expect("contexts poisoned");
        if let Some(&ptr) = registry.get(&self.tag) {
            unsafe { &*(ptr as *const TraceContext) }
                .listeners
                .lock()
                .expect("listeners poisoned")
                .remove(&self.id);
        }
    }
}
/// Every event: a connection with a listener, or under the SQL profile.
const TRACE_ALL: u32 = ffi::SQLITE_TRACE_STMT
    | ffi::SQLITE_TRACE_CLOSE
    | ffi::SQLITE_TRACE_ROW
    | ffi::SQLITE_TRACE_PROFILE;
/// Attribution needs STMT and CLOSE only; the profile needs every event.
fn trace_mask(profiling: bool) -> u32 {
    if profiling {
        TRACE_ALL
    } else {
        ffi::SQLITE_TRACE_STMT | ffi::SQLITE_TRACE_CLOSE
    }
}
/// Once attached, a connection retains ROW and PROFILE callbacks until CLOSE.
/// Only test and measurement code attaches listeners, so this callback cost is accepted.
pub fn attach_listener(conn: &Connection, listener: Listener) -> ListenerGuard {
    // SAFETY: the registry is populated only by install and removed on a
    // successful CLOSE; Connection borrows the handle for the guard lifetime.
    unsafe {
        let db = conn.handle();
        if !tags()
            .lock()
            .expect("tag registry poisoned")
            .contains_key(&(db as usize))
        {
            install(conn, ConnectionRole::Ephemeral);
        }
        let tag = tags().lock().expect("tag registry poisoned")[&(db as usize)];
        let ptr = contexts().lock().expect("contexts poisoned")[&tag] as *mut TraceContext;
        let context = &*ptr;
        let id = context
            .next_listener
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut listeners = context.listeners.lock().expect("listeners poisoned");
        listeners.insert(id, listener);
        ffi::sqlite3_trace_v2(db, TRACE_ALL, Some(trace_callback), ptr.cast());
        ListenerGuard { tag, id }
    }
}
type CloseHooks = Mutex<Vec<fn(ConnectionTag)>>;
static CLOSE_HOOKS: OnceLock<CloseHooks> = OnceLock::new();
fn close_hooks() -> &'static CloseHooks {
    CLOSE_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}
pub fn on_connection_close(hook: fn(ConnectionTag)) {
    let mut hooks = close_hooks().lock().expect("close hooks poisoned");
    if !hooks
        .iter()
        .any(|existing| std::ptr::fn_addr_eq(*existing, hook))
    {
        hooks.push(hook);
    }
}
static CONTEXTS: OnceLock<Mutex<HashMap<ConnectionTag, usize>>> = OnceLock::new();
fn contexts() -> &'static Mutex<HashMap<ConnectionTag, usize>> {
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Names the JSON-lines dump file. Unset means no instrument at all.
pub const PROFILE_PATH_ENV: &str = "BIFROST_SQL_PROFILE";

/// Distinct (role, SQL text) pairs the aggregate keeps.
///
/// Distinct statement texts are a property of the code, not of the workspace:
/// the store has about 500 `prepare` call sites across nine connection roles,
/// so this cap is roughly an order of magnitude of headroom. A statement built
/// by `format!` with values inlined instead of bound would break that property,
/// which is why the cap exists and why everything past it lands in one
/// [`Overflow`] bucket the dump reports: an overflowing family is also a
/// prepared-statement-cache problem.
const STATEMENT_CAP: usize = 4096;

/// Bytes of expanded SQL kept as the first-seen sample of a statement.
///
/// The ledger prepares each statement from this sample so the planner sees real
/// bindings. A batch insert's expanded text can be far larger than its useful
/// sample, so it is capped and the dump records that it was capped; the ledger
/// falls back to the unexpanded text for those.
const EXPANDED_SAMPLE_CAP_BYTES: usize = 16 * 1024;

/// How often the background writer rewrites the dump.
///
/// A process killed by `timeout` (the warm `usage_graph` workload does not
/// finish) never closes its connections and never returns from `main`, so the
/// dump cannot be written only at exit. The whole aggregate is rewritten
/// atomically, so a killed process loses at most this much of its tail.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Distinct expanded statement invocations retained per request. The profile
/// only needs enough identities to establish repeated key reads; this cap
/// bounds request-local diagnostic memory on whole-workspace operations.
const REQUEST_BINDING_CAP: usize = 1 << 21;

/// Which opener produced the connection a statement ran on.
///
/// The role is a property of the open site, not of the caller: the garbage
/// collector and the store writer both open through `open_unified_connection`
/// and both record as [`ConnectionRole::Writer`]. The workload label on the
/// dump file is what separates them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub(crate) enum ConnectionRole {
    Writer,
    Reader,
    SessionReader,
    StreamingReader,
    UpgradeSource,
    UpgradeTarget,
    VersionProbe,
    Cleanup,
    Ephemeral,
}

struct ActiveStatement {
    statement: usize,
    role: ConnectionRole,
    keys: Option<usize>,
    rows: u64,
}

thread_local! {
    static ACTIVE_STATEMENTS: RefCell<Vec<ActiveStatement>> = const { RefCell::new(Vec::new()) };
    static LOGICAL_KEY_COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

#[derive(Default)]
struct RequestStatement {
    sql: String,
    role: Option<ConnectionRole>,
    executions: u64,
    total_nanos: u128,
    max_nanos: u64,
    rows: u64,
    decoded_rows: u64,
    row_histogram: HashMap<u64, u64>,
    key_histogram: HashMap<u64, u64>,
    repeated_expanded_invocations: u64,
    untracked_expanded_invocations: u64,
}

struct RequestAggregate {
    tool: String,
    started: Instant,
    overlapped: bool,
    /// The process-wide counters at scope start; `None` when counters are off.
    counters_before: Option<HashMap<&'static str, u64>>,
    /// The counters when the request closed, taken under the request lock so the
    /// next request's start snapshot cannot precede it; `None` while open or
    /// when counters are off.
    counters_after: Option<HashMap<&'static str, u64>>,
    statements: HashMap<u64, RequestStatement>,
    seen_bindings: HashSet<(u64, u64)>,
    internal_rows: [u64; ConnectionRole::ALL.len()],
}

impl RequestAggregate {
    fn new(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            started: Instant::now(),
            overlapped: false,
            counters_before: crate::profiling::counters_snapshot(),
            counters_after: None,
            statements: HashMap::new(),
            seen_bindings: HashSet::new(),
            internal_rows: [0; ConnectionRole::ALL.len()],
        }
    }

    fn record(
        &mut self,
        role: ConnectionRole,
        sql: &str,
        expanded: Option<&str>,
        elapsed: Duration,
        keys: Option<usize>,
        rows: u64,
    ) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let family = self.ensure_statement(role, sql);
        let statement = self
            .statements
            .get_mut(&family)
            .expect("statement was inserted");
        statement.executions += 1;
        statement.total_nanos += u128::from(nanos);
        statement.max_nanos = statement.max_nanos.max(nanos);
        statement.rows += rows;
        *statement.row_histogram.entry(rows).or_default() += 1;
        if let Some(keys) = keys {
            *statement.key_histogram.entry(keys as u64).or_default() += 1;
        }
        let Some(expanded) = expanded else {
            statement.untracked_expanded_invocations += 1;
            return;
        };
        let mut binding_hasher = DefaultHasher::new();
        expanded.hash(&mut binding_hasher);
        let binding = (family, binding_hasher.finish());
        if self.seen_bindings.contains(&binding) {
            statement.repeated_expanded_invocations += 1;
        } else if self.seen_bindings.len() < REQUEST_BINDING_CAP {
            self.seen_bindings.insert(binding);
        } else {
            statement.untracked_expanded_invocations += 1;
        }
    }

    fn ensure_statement(&mut self, role: ConnectionRole, sql: &str) -> u64 {
        assert!(!sql.is_empty(), "profiled statements must have SQL");
        let mut family_hasher = DefaultHasher::new();
        role.hash(&mut family_hasher);
        sql.hash(&mut family_hasher);
        let family = family_hasher.finish();
        let statement = self.statements.entry(family).or_default();
        if statement.role.is_none() {
            statement.role = Some(role);
            statement.sql = sql.to_string();
        }
        family
    }

    fn record_decoded_row(&mut self, role: ConnectionRole, sql: &str) {
        if sql.is_empty() {
            self.internal_rows[role as usize] += 1;
        } else {
            let family = self.ensure_statement(role, sql);
            self.statements
                .get_mut(&family)
                .expect("statement was inserted")
                .decoded_rows += 1;
        }
    }

    fn render(self) -> String {
        let mut statements = self
            .statements
            .into_values()
            .map(|statement| {
                let key_samples = statement.key_histogram.values().sum::<u64>();
                let one_key_executions = statement.key_histogram.get(&1).copied().unwrap_or(0);
                let row_histogram = statement
                    .row_histogram
                    .into_iter()
                    .map(|(key, count)| (key.to_string(), count))
                    .collect::<std::collections::BTreeMap<_, _>>();
                let key_histogram = statement
                    .key_histogram
                    .into_iter()
                    .map(|(key, count)| (key.to_string(), count))
                    .collect::<std::collections::BTreeMap<_, _>>();
                serde_json::json!({
                    "kind": "statement",
                    "decoded_rows": statement.decoded_rows,
                    "role": statement.role.expect("profiled statement role is set").as_str(),
                    "sql": statement.sql,
                    "executions": statement.executions,
                    "total_nanos": statement.total_nanos.to_string(),
                    "max_nanos": statement.max_nanos,
                    "rows": statement.rows,
                    "row_histogram": row_histogram,
                    "key_histogram": key_histogram,
                    "key_samples": key_samples,
                    "one_key_executions": one_key_executions,
                    "repeated_expanded_invocations": statement.repeated_expanded_invocations,
                    "untracked_expanded_invocations": statement.untracked_expanded_invocations,
                })
            })
            .collect::<Vec<_>>();
        statements.sort_by(|left, right| {
            left["role"]
                .as_str()
                .cmp(&right["role"].as_str())
                .then_with(|| left["sql"].as_str().cmp(&right["sql"].as_str()))
        });
        let mut record = serde_json::json!({
            "kind": "request",
            "tool": self.tool,
            "wall_ms": self.started.elapsed().as_secs_f64() * 1000.0,
            "overlapped": self.overlapped,
            "expanded_binding_cap": REQUEST_BINDING_CAP,
            "distinct_expanded_bindings": self.seen_bindings.len(),
            "statements": statements,
            "sqlite_internal_rows": internal_row_records(&self.internal_rows),
        });
        if let (Some(before), Some(after)) = (&self.counters_before, &self.counters_after) {
            record["counters"] = serde_json::json!(crate::profiling::counters_delta(before, after));
        }
        record.to_string()
    }
}

/// A request-local SQL family profile. Its statement totals and histograms are
/// written beside the process-wide dump by replacing its extension with
/// `requests.jsonl`.
pub struct RequestScope {
    profile: Option<&'static Profile>,
    counted: bool,
}

/// Restore the caller's logical-key cardinality after a reader method returns.
pub struct KeyScope {
    previous: Option<usize>,
    active: bool,
}

impl ConnectionRole {
    const ALL: [Self; 9] = [
        Self::Writer,
        Self::Reader,
        Self::SessionReader,
        Self::StreamingReader,
        Self::UpgradeSource,
        Self::UpgradeTarget,
        Self::VersionProbe,
        Self::Cleanup,
        Self::Ephemeral,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Reader => "reader",
            Self::SessionReader => "session_reader",
            Self::StreamingReader => "streaming_reader",
            Self::UpgradeSource => "upgrade_source",
            Self::UpgradeTarget => "upgrade_target",
            Self::VersionProbe => "version_probe",
            Self::Cleanup => "cleanup",
            Self::Ephemeral => "ephemeral",
        }
    }
}

// SQLite counters are cumulative for one prepared statement, not one execution.
// Summing their values at every callback would count earlier runs repeatedly.
#[derive(Default)]
struct StatementReuse {
    first_run_executions: u64,
    reused_executions: u64,
    executions_with_reprepare_on_every_run: u64,
    max_statement_runs: i32,
    max_statement_reprepares: i32,
}

impl StatementReuse {
    fn observe(&mut self, runs: i32, reprepares: i32) {
        self.first_run_executions += u64::from(runs == 1);
        self.reused_executions += u64::from(runs > 1);
        self.executions_with_reprepare_on_every_run += u64::from(runs > 0 && reprepares == runs);
        self.max_statement_runs = self.max_statement_runs.max(runs);
        self.max_statement_reprepares = self.max_statement_reprepares.max(reprepares);
    }
}

struct Statement {
    reuse: StatementReuse,
    executions: u64,
    decoded_rows: u64,
    total_nanos: u128,
    max_nanos: u64,
    rows: u64,
    /// First seen, capped at [`EXPANDED_SAMPLE_CAP_BYTES`]. `None` when SQLite
    /// could not expand the statement.
    expanded_sample: Option<String>,
    expanded_truncated: bool,
}

/// Everything [`STATEMENT_CAP`] pushed out, in one bucket. The first statement
/// to overflow names the family for the report.
#[derive(Default)]
struct Overflow {
    reuse: StatementReuse,
    executions: u64,
    decoded_rows: u64,
    total_nanos: u128,
    max_nanos: u64,
    rows: u64,
    first: Option<(ConnectionRole, String)>,
}

/// SQLite suppresses SQL text and completion events while loading its schema.
#[derive(Clone, Copy, serde::Serialize)]
enum InternalRowReason {
    #[serde(rename = "sqlite_schema_or_statistics_statement")]
    SchemaOrStatisticsStatement,
}

fn profile_header() -> serde_json::Value {
    serde_json::json!({"kind": "profile_header", "format_version": 2})
}

fn internal_row_records(rows: &[u64; ConnectionRole::ALL.len()]) -> Vec<serde_json::Value> {
    ConnectionRole::ALL
        .iter()
        .zip(rows)
        .filter(|(_, decoded_rows)| **decoded_rows > 0)
        .map(|(role, &decoded_rows)| {
            serde_json::json!({
                "kind": "sqlite_internal_rows",
                "role": role.as_str(),
                "decoded_rows": decoded_rows,
                "reason": InternalRowReason::SchemaOrStatisticsStatement,
            })
        })
        .collect()
}

struct Aggregate {
    /// One map per role, so a repeat execution finds its entry without
    /// allocating a key.
    by_role: [HashMap<String, Statement>; ConnectionRole::ALL.len()],
    internal_rows: [u64; ConnectionRole::ALL.len()],
    distinct: usize,
    decoded_rows: u64,
    overflow: Overflow,
    /// Starts true so the first flush writes a dump even for a process that
    /// issued no statement at all.
    dirty: bool,
}

struct Profile {
    path: PathBuf,
    aggregate: Mutex<Aggregate>,
    request_output: Mutex<Option<std::fs::File>>,
    active_request: Mutex<Option<RequestAggregate>>,
}

impl Profile {
    fn new(path: PathBuf) -> Self {
        let request_path = path.with_extension("requests.jsonl");
        let request_output = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&request_path)
            .and_then(|mut file| {
                writeln!(file, "{}", profile_header())?;
                file.flush()?;
                Ok(file)
            }) {
            Ok(file) => Some(file),
            Err(error) => {
                eprintln!(
                    "Bifrost SQL request profile could not create {}: {error}",
                    request_path.display()
                );
                None
            }
        };
        Self {
            path,
            aggregate: Mutex::new(Aggregate {
                by_role: std::array::from_fn(|_| HashMap::new()),
                internal_rows: [0; ConnectionRole::ALL.len()],
                distinct: 0,
                decoded_rows: 0,
                overflow: Overflow::default(),
                dirty: true,
            }),
            request_output: Mutex::new(request_output),
            active_request: Mutex::new(None),
        }
    }

    fn record_request_statement(
        &self,
        role: ConnectionRole,
        sql: &str,
        expanded: Option<&str>,
        elapsed: Duration,
        keys: Option<usize>,
        rows: u64,
    ) {
        if let Some(request) = self
            .active_request
            .lock()
            .expect("SQL request profile poisoned")
            .as_mut()
        {
            request.record(role, sql, expanded, elapsed, keys, rows);
        }
    }

    fn finish_request(&self, request: RequestAggregate) {
        #[cfg(test)]
        if let Some(hook) = TEST_FINISH_HOOK.get() {
            hook(&request.tool);
        }
        let line = request.render();
        let mut output = self
            .request_output
            .lock()
            .expect("SQL request profile output poisoned");
        if let Some(output) = output.as_mut()
            && let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush())
        {
            eprintln!("Bifrost SQL request profile could not write a line: {error}");
        }
    }
}

static PROFILE: OnceLock<Option<Profile>> = OnceLock::new();

/// The test seam. The environment is read once and its answer is kept, which is
/// what a process wants and what makes both halves of the behaviour
/// untestable in one process: the unset half has to be observed before the set
/// half exists. This lets the test observe the unset half first and then turn
/// the instrument on.
#[cfg(test)]
static TEST_PROFILE: OnceLock<Profile> = OnceLock::new();

/// Runs with the request's tool name after its lock is released and before it
/// renders, so a test can hold one request in that window.
#[cfg(test)]
static TEST_FINISH_HOOK: OnceLock<TestFinishHook> = OnceLock::new();

#[cfg(test)]
type TestFinishHook = Box<dyn Fn(&str) + Send + Sync>;

/// The process's profile, or `None` when [`PROFILE_PATH_ENV`] is unset. The
/// environment is read exactly once, on the first store connection.
fn profile() -> Option<&'static Profile> {
    #[cfg(test)]
    if let Some(profile) = TEST_PROFILE.get() {
        return Some(profile);
    }
    PROFILE
        .get_or_init(|| std::env::var_os(PROFILE_PATH_ENV).map(|path| Profile::new(path.into())))
        .as_ref()
}

/// Open a per-MCP-request SQL profile. The full statement family table is
/// appended to the sidecar named by [`PROFILE_PATH_ENV`] when this scope drops.
pub fn request_scope(tool: &str) -> RequestScope {
    let Some(profile) = profile() else {
        return RequestScope {
            profile: None,
            counted: false,
        };
    };
    let mut active = profile
        .active_request
        .lock()
        .expect("SQL request profile poisoned");
    if let Some(active) = active.as_mut() {
        active.overlapped = true;
        return RequestScope {
            profile: Some(profile),
            counted: false,
        };
    }
    *active = Some(RequestAggregate::new(tool));
    RequestScope {
        profile: Some(profile),
        counted: true,
    }
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let Some(profile) = self.profile else {
            return;
        };
        let request = {
            let mut active = profile
                .active_request
                .lock()
                .expect("SQL request profile poisoned");
            let mut request = active
                .take()
                .expect("counted SQL request scope owns an open request");
            // Still under the lock: a request opened after this guard drops
            // snapshots its start later, so no event is in two records.
            request.counters_after = crate::profiling::counters_snapshot();
            request
        };
        profile.finish_request(request);
    }
}

/// Set the logical key count for SQL statements issued by the current reader
/// method. Nested reader methods restore the previous count on return.
pub fn key_scope(keys: usize) -> KeyScope {
    if profile().is_none() {
        return KeyScope {
            previous: None,
            active: false,
        };
    }
    let previous = LOGICAL_KEY_COUNT.with(|count| count.replace(Some(keys)));
    KeyScope {
        previous,
        active: true,
    }
}

impl Drop for KeyScope {
    fn drop(&mut self) {
        if self.active {
            LOGICAL_KEY_COUNT.with(|count| count.set(self.previous));
        }
    }
}

/// Include a durable semantic catalog in the existing SQL profile.
pub fn install_catalog_durable(conn: &Connection) {
    install(conn, ConnectionRole::Writer);
}

/// Include the session catalog in the existing SQL profile.
pub fn install_catalog_session(conn: &Connection) {
    install(conn, ConnectionRole::SessionReader);
}

/// Include an immutable active-set reader in the existing SQL profile.
pub fn install_catalog_active(conn: &Connection) {
    install(conn, ConnectionRole::Reader);
}

type TestStatementObserver = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

thread_local! {
    static TEST_SUBSCRIBERS: RefCell<Vec<(usize, TestStatementObserver)>> = const { RefCell::new(Vec::new()) };
    static NEXT_SUBSCRIBER: Cell<usize> = const { Cell::new(0) };
}

fn notify_test_subscribers(sql: &str) {
    TEST_SUBSCRIBERS.with(|subscribers| {
        for (_, subscriber) in subscribers.borrow().iter() {
            subscriber(sql);
        }
    });
}

/// A thread-local test observer. The connection's permanent trace hook remains installed.
#[cfg(any(test, feature = "test-support"))]
pub struct TestStatementSubscription {
    id: usize,
}

#[cfg(any(test, feature = "test-support"))]
pub fn subscribe_test_statements(
    _conn: &Connection,
    subscriber: std::sync::Arc<dyn Fn(&str) + Send + Sync>,
) -> TestStatementSubscription {
    let id = NEXT_SUBSCRIBER.with(|next| {
        let id = next.get();
        next.set(id + 1);
        id
    });
    TEST_SUBSCRIBERS.with(|subscribers| subscribers.borrow_mut().push((id, subscriber)));
    TestStatementSubscription { id }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TestStatementSubscription {
    fn drop(&mut self) {
        TEST_SUBSCRIBERS
            .with(|subscribers| subscribers.borrow_mut().retain(|(id, _)| *id != self.id));
    }
}

/// Install the statement dispatcher on one analyzer-store connection.
/// The profile collector is attached only when configured.
pub(crate) fn install(conn: &Connection, role: ConnectionRole) {
    let profiling = profile().is_some();
    static FLUSHER: Once = Once::new();
    if profiling {
        FLUSHER.call_once(|| {
            let spawned = std::thread::Builder::new()
                .name("bifrost-sql-profile".to_string())
                .spawn(|| {
                    loop {
                        std::thread::sleep(FLUSH_INTERVAL);
                        flush();
                    }
                });
            if let Err(error) = spawned {
                eprintln!("Bifrost SQL profile has no background writer: {error}");
            }
        });
    }
    // SAFETY: Connection owns db; SQLite calls CLOSE before freeing it. A busy
    // close keeps this context because sqlite3Close (sqlite3.c:188462,188481)
    // traces before connectionIsBusy. sqlite3_next_stmt sees db->pVdbe;
    // connectionIsBusy also checks online backups (sqlite3.c:188438), but
    // rusqlite Backup borrows both connections and Bifrost's Connection::backup
    // finishes before returning (cache_db.rs:1790). rusqlite uses sqlite3_close
    // (inner_connection.rs:139-165) and Drop calls close (:412-417).
    unsafe {
        let db = conn.handle();
        let existing_tag = tags()
            .lock()
            .expect("tag registry poisoned")
            .get(&(db as usize))
            .copied();
        if let Some(tag) = existing_tag {
            let existing = contexts().lock().expect("contexts poisoned")[&tag];
            // Catalog readers reopen the role on the same connection after
            // db::open. The borrowed Connection excludes concurrent use.
            (*(existing as *const TraceContext))
                .role
                .store(role as u8, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let context = Box::into_raw(Box::new(TraceContext {
            tag: ConnectionTag::next(),
            role: std::sync::atomic::AtomicU8::new(role as u8),
            db,
            profiling,
            listeners: Mutex::new(HashMap::new()),
            next_listener: std::sync::atomic::AtomicU64::new(1),
        }));
        tags()
            .lock()
            .expect("tag registry poisoned")
            .insert(db as usize, (*context).tag);
        contexts()
            .lock()
            .expect("contexts poisoned")
            .insert((*context).tag, context as usize);
        ffi::sqlite3_trace_v2(
            db,
            trace_mask(profiling),
            Some(trace_callback),
            context.cast(),
        );
    }
}
// SAFETY: SQLite supplies a live TraceContext pointer installed above; stmt
// pointers are valid for this callback. On CLOSE, free only when no statements
// remain, because sqlite3Close reports CLOSE before a possible SQLITE_BUSY.
unsafe extern "C" fn trace_callback(
    code: u32,
    raw: *mut c_void,
    p: *mut c_void,
    x: *mut c_void,
) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let context = &*(raw as *mut TraceContext);
        if code == ffi::SQLITE_TRACE_CLOSE {
            if ffi::sqlite3_next_stmt(context.db, std::ptr::null_mut()).is_null() {
                // Hold the registry lock through free so a guard on another
                // thread cannot dereference this context after CLOSE.
                let mut registry = contexts().lock().expect("contexts poisoned");
                registry.remove(&context.tag);
                tags()
                    .lock()
                    .expect("tag registry poisoned")
                    .remove(&(context.db as usize));
                if context.profiling {
                    flush();
                }
                let tag = context.tag;
                drop(Box::from_raw(raw as *mut TraceContext));
                drop(registry);
                let hooks = close_hooks().lock().expect("close hooks poisoned").clone();
                for hook in hooks {
                    hook(tag);
                }
            }
            return ffi::SQLITE_OK;
        }
        let stmt = p as *mut ffi::sqlite3_stmt;
        let sql_ptr = ffi::sqlite3_sql(stmt);
        let sql = (!sql_ptr.is_null()).then(|| CStr::from_ptr(sql_ptr).to_string_lossy());
        let sql_text = sql.as_deref().unwrap_or("");
        if code == ffi::SQLITE_TRACE_STMT {
            // Attribution failing closed must not depend on the listeners below.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::attribution::statement_started(sql_text, context.tag)
            }))
            .is_err()
            {
                crate::attribution::statement_lost();
            }
            notify_test_subscribers(sql_text);
        }
        // A once-listened connection retains ROW and PROFILE callbacks for life.
        // Skip dispatch when neither a listener nor profiling needs them.
        if (code == ffi::SQLITE_TRACE_ROW || code == ffi::SQLITE_TRACE_PROFILE)
            && !context.profiling
            && context
                .listeners
                .lock()
                .expect("listeners poisoned")
                .is_empty()
        {
            return ffi::SQLITE_OK;
        }
        if code == ffi::SQLITE_TRACE_STMT
            || code == ffi::SQLITE_TRACE_ROW
            || code == ffi::SQLITE_TRACE_PROFILE
        {
            let event = match code {
                ffi::SQLITE_TRACE_STMT => ListenerEvent::Statement {
                    statement: stmt as usize,
                    sql: (!x.is_null())
                        .then(|| CStr::from_ptr(x.cast()).to_str().ok())
                        .flatten(),
                },
                ffi::SQLITE_TRACE_ROW => ListenerEvent::Row {
                    statement: stmt as usize,
                    sql: sql.as_deref(),
                },
                _ => ListenerEvent::Profile {
                    statement: stmt as usize,
                    sql: sql.as_deref(),
                    elapsed: Duration::from_nanos(*(x as *const u64)),
                },
            };
            let listeners = context
                .listeners
                .lock()
                .expect("listeners poisoned")
                .values()
                .map(Arc::clone)
                .collect::<Vec<_>>();
            #[cfg(test)]
            if code == ffi::SQLITE_TRACE_ROW {
                ROW_DISPATCHES.with(|count| count.set(count.get() + 1));
            }
            // A panicking listener loses only its own event; the others still
            // see it. The panic hook has already reported the panic.
            for listener in listeners {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| listener(event)))
                    .is_err()
                {
                    eprintln!("analyzer SQL listener panicked; its event was dropped");
                }
            }
        }
        if !context.profiling {
            return ffi::SQLITE_OK;
        }
        let role = ConnectionRole::ALL
            [usize::from(context.role.load(std::sync::atomic::Ordering::Relaxed))];
        match code {
            ffi::SQLITE_TRACE_STMT => {
                ACTIVE_STATEMENTS.with(|current| {
                    let mut current = current.borrow_mut();
                    // SQLite repeats STMT for trigger subprograms with the same
                    // prepared-statement pointer, then emits one PROFILE when
                    // that execution finishes. Retain one frame per execution.
                    if current
                        .iter()
                        .any(|active| active.statement == stmt as usize)
                    {
                        return;
                    }
                    current.push(ActiveStatement {
                        statement: stmt as usize,
                        role,
                        keys: LOGICAL_KEY_COUNT.with(Cell::get),
                        rows: 0,
                    });
                });
            }
            ffi::SQLITE_TRACE_ROW => {
                ACTIVE_STATEMENTS.with(|current| {
                    if let Some(active) = current.borrow_mut().last_mut() {
                        active.rows += 1;
                    }
                });
                record_decoded_row(role, sql_text);
            }
            ffi::SQLITE_TRACE_PROFILE => {
                let elapsed = Duration::from_nanos(*(x as *const i64) as u64);
                let (keys, rows) = ACTIVE_STATEMENTS.with(|current| {
                    let mut active = current.borrow_mut();
                    active
                        .iter()
                        .rposition(|entry| entry.role == role && entry.statement == stmt as usize)
                        .map(|index| active.remove(index))
                        .map_or((None, 0), |entry| (entry.keys, entry.rows))
                });
                let expanded_ptr = ffi::sqlite3_expanded_sql(stmt);
                let expanded = if expanded_ptr.is_null() {
                    None
                } else {
                    let value = CStr::from_ptr(expanded_ptr).to_string_lossy().into_owned();
                    ffi::sqlite3_free(expanded_ptr.cast());
                    Some(value)
                };
                record(
                    role,
                    sql_text,
                    expanded.clone(),
                    elapsed,
                    ffi::sqlite3_stmt_status(stmt, ffi::SQLITE_STMTSTATUS_RUN, 0),
                    ffi::sqlite3_stmt_status(stmt, ffi::SQLITE_STMTSTATUS_REPREPARE, 0),
                    rows,
                );
                if let Some(profile) = profile() {
                    profile.record_request_statement(
                        role,
                        sql_text,
                        expanded.as_deref(),
                        elapsed,
                        keys,
                        rows,
                    );
                }
            }
            _ => {}
        }
        ffi::SQLITE_OK
    }));
    if result.is_err() && code == ffi::SQLITE_TRACE_STMT {
        crate::attribution::statement_lost();
    }
    ffi::SQLITE_OK
}

fn record_decoded_row(role: ConnectionRole, sql: &str) {
    let Some(profile) = profile() else {
        return;
    };
    if let Some(request) = profile
        .active_request
        .lock()
        .expect("SQL request profile poisoned")
        .as_mut()
    {
        request.record_decoded_row(role, sql);
    }
    let mut aggregate = profile
        .aggregate
        .lock()
        .expect("SQL profile aggregate poisoned");
    aggregate.decoded_rows = aggregate
        .decoded_rows
        .checked_add(1)
        .expect("SQL profile decoded row count fits u64");
    let index = role as usize;
    if sql.is_empty() {
        aggregate.internal_rows[index] += 1;
    } else if let Some(statement) = aggregate.by_role[index].get_mut(sql) {
        statement.decoded_rows = statement
            .decoded_rows
            .checked_add(1)
            .expect("statement decoded row count fits u64");
    } else if aggregate.distinct < STATEMENT_CAP {
        assert!(!sql.is_empty(), "profiled statements must have SQL");
        aggregate.distinct += 1;
        aggregate.by_role[index].insert(
            sql.to_string(),
            Statement {
                reuse: StatementReuse::default(),
                executions: 0,
                decoded_rows: 1,
                total_nanos: 0,
                max_nanos: 0,
                rows: 0,
                expanded_sample: None,
                expanded_truncated: false,
            },
        );
    } else {
        aggregate.overflow.decoded_rows = aggregate
            .overflow
            .decoded_rows
            .checked_add(1)
            .expect("overflow decoded row count fits u64");
        aggregate
            .overflow
            .first
            .get_or_insert_with(|| (role, sql.to_string()));
    }
    aggregate.dirty = true;
}

fn record(
    role: ConnectionRole,
    sql: &str,
    expanded: Option<String>,
    elapsed: Duration,
    runs: i32,
    reprepares: i32,
    rows: u64,
) {
    assert!(!sql.is_empty(), "profiled statements must have SQL");
    let profile = profile().expect("SQL profile hook installed without a profile");
    let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    let mut aggregate = profile
        .aggregate
        .lock()
        .expect("SQL profile aggregate poisoned");
    aggregate.dirty = true;
    let index = role as usize;
    if let Some(statement) = aggregate.by_role[index].get_mut(sql) {
        statement.reuse.observe(runs, reprepares);
        statement.executions += 1;
        statement.total_nanos += u128::from(nanos);
        statement.max_nanos = statement.max_nanos.max(nanos);
        statement.rows = statement.rows.saturating_add(rows);
        if statement.expanded_sample.is_none() && !statement.expanded_truncated {
            (statement.expanded_sample, statement.expanded_truncated) = expanded_sample(expanded);
        }
        return;
    }
    if aggregate.distinct >= STATEMENT_CAP {
        let overflow = &mut aggregate.overflow;
        overflow.reuse.observe(runs, reprepares);
        overflow.executions += 1;
        overflow.total_nanos += u128::from(nanos);
        overflow.max_nanos = overflow.max_nanos.max(nanos);
        overflow.rows = overflow.rows.saturating_add(rows);
        overflow
            .first
            .get_or_insert_with(|| (role, sql.to_string()));
        return;
    }
    aggregate.distinct += 1;
    let (expanded_sample, expanded_truncated) = expanded_sample(expanded);
    let mut reuse = StatementReuse::default();
    reuse.observe(runs, reprepares);
    aggregate.by_role[index].insert(
        sql.to_string(),
        Statement {
            reuse,
            executions: 1,
            decoded_rows: 0,
            total_nanos: u128::from(nanos),
            max_nanos: nanos,
            rows,
            expanded_sample,
            expanded_truncated,
        },
    );
}

fn expanded_sample(expanded: Option<String>) -> (Option<String>, bool) {
    match expanded {
        Some(text) => {
            let truncated = text.len() > EXPANDED_SAMPLE_CAP_BYTES;
            let mut end = EXPANDED_SAMPLE_CAP_BYTES.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            (Some(text[..end].to_string()), truncated)
        }
        None => (None, false),
    }
}

/// Executions and total nanoseconds over every statement recorded so far, or
/// `None` when the instrument is off.
///
/// This is a whole-process running total, not a per-statement snapshot. The
/// seam profile takes it at each end of a request boundary and reports the
/// difference, which gives a request its SQL volume and time for the cost of
/// one walk over the aggregate's few hundred entries. A per-statement delta
/// would mean snapshotting and writing those entries once per request, which is
/// a different instrument.
pub fn totals() -> Option<(u64, u128)> {
    let (executions, _, nanos) = totals_with_rows()?;
    Some((executions, nanos))
}

/// Executions, SQLite rows yielded, and total nanoseconds recorded so far, or
/// `None` when the instrument is off. The row count includes SQLite internal
/// schema rows, matching the selected-operation trace used by point-work pins.
pub fn totals_with_rows() -> Option<(u64, u64, u128)> {
    let profile = profile()?;
    let aggregate = profile
        .aggregate
        .lock()
        .expect("SQL profile aggregate poisoned");
    let mut executions = aggregate.overflow.executions;
    let mut nanos = aggregate.overflow.total_nanos;
    let mut rows = aggregate.overflow.rows;
    for statements in &aggregate.by_role {
        for statement in statements.values() {
            executions += statement.executions;
            nanos += statement.total_nanos;
            rows = rows.saturating_add(statement.rows);
        }
    }
    Some((executions, aggregate.decoded_rows, nanos))
}

/// Write the dump now. The background writer calls this; a long-lived server
/// path that wants a mid-run snapshot can call it too. With the variable unset
/// it does nothing.
pub fn flush() {
    let Some(profile) = profile() else {
        return;
    };
    let Some(dump) = render(profile) else {
        return;
    };
    // The whole dump is rewritten every time, so a reader either sees the
    // previous complete file or the new one.
    let staged = profile
        .path
        .with_extension(format!("{}.tmp", std::process::id()));
    if let Err(error) = write_dump(&staged, &dump)
        .and_then(|()| std::fs::rename(&staged, &profile.path).map_err(|err| err.to_string()))
    {
        eprintln!(
            "Bifrost SQL profile could not write {}: {error}",
            profile.path.display()
        );
    }
}

fn write_dump(staged: &std::path::Path, dump: &str) -> Result<(), String> {
    let mut file = std::fs::File::create(staged).map_err(|error| error.to_string())?;
    file.write_all(dump.as_bytes())
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

/// Serialize the aggregate under the lock and release it before any file I/O,
/// so a flush never stalls the statements it is measuring on the filesystem.
/// The `dirty` flag is cleared in the same critical section that snapshots the
/// rows, so a statement recorded during the write is not lost from the next
/// flush.
fn render(profile: &Profile) -> Option<String> {
    let mut aggregate = profile
        .aggregate
        .lock()
        .expect("SQL profile aggregate poisoned");
    if !aggregate.dirty {
        return None;
    }
    aggregate.dirty = false;
    let mut dump = profile_header().to_string();
    dump.push('\n');
    dump.push_str(
        &serde_json::json!({
            "kind": "header",
            "pid": std::process::id(),
            "statement_cap": STATEMENT_CAP,
            "expanded_sample_cap_bytes": EXPANDED_SAMPLE_CAP_BYTES,
            "distinct_statements": aggregate.distinct,
            "decoded_rows": aggregate.decoded_rows,
            "flush_interval_ms": FLUSH_INTERVAL.as_millis(),
        })
        .to_string(),
    );
    dump.push('\n');
    for (role, statements) in ConnectionRole::ALL.iter().zip(aggregate.by_role.iter()) {
        for (sql, statement) in statements {
            dump.push_str(
                &serde_json::json!({
                    "kind": "statement",
                    "role": role.as_str(),
                    "sql": sql,
                    "executions": statement.executions,
                    "decoded_rows": statement.decoded_rows,
                    "first_run_executions": statement.reuse.first_run_executions,
                    "reused_executions": statement.reuse.reused_executions,
                    "executions_with_reprepare_on_every_run": statement.reuse.executions_with_reprepare_on_every_run,
                    "max_statement_runs": statement.reuse.max_statement_runs,
                    "max_statement_reprepares": statement.reuse.max_statement_reprepares,
                    "total_nanos": statement.total_nanos.to_string(),
                    "max_nanos": statement.max_nanos,
                    "rows": statement.rows,
                    "expanded_sql": statement.expanded_sample,
                    "expanded_truncated": statement.expanded_truncated,
                })
                .to_string(),
            );
            dump.push('\n');
        }
    }
    for internal in internal_row_records(&aggregate.internal_rows) {
        dump.push_str(&internal.to_string());
        dump.push('\n');
    }
    if let Some((role, sql)) = &aggregate.overflow.first {
        dump.push_str(
            &serde_json::json!({
                "kind": "overflow",
                "first_role": role.as_str(),
                "first_sql": sql,
                "executions": aggregate.overflow.executions,
                "decoded_rows": aggregate.overflow.decoded_rows,
                "first_run_executions": aggregate.overflow.reuse.first_run_executions,
                "reused_executions": aggregate.overflow.reuse.reused_executions,
                "executions_with_reprepare_on_every_run": aggregate.overflow.reuse.executions_with_reprepare_on_every_run,
                "max_statement_runs": aggregate.overflow.reuse.max_statement_runs,
                "max_statement_reprepares": aggregate.overflow.reuse.max_statement_reprepares,
                "total_nanos": aggregate.overflow.total_nanos.to_string(),
                "max_nanos": aggregate.overflow.max_nanos,
                "rows": aggregate.overflow.rows,
            })
            .to_string(),
        );
        dump.push('\n');
    }
    Some(dump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{self, AttributionFrame};
    use crate::cache_db::{cache_db_file_name, open_readonly_connection, open_unified_connection};
    use brokk_bifrost_test_macros::hardwon;

    struct Seen(Mutex<Vec<ConnectionTag>>);
    impl AttributionFrame for Seen {
        fn mark_unattributed(&self, _: &str, _: Option<&'static str>, tag: ConnectionTag) {
            self.0.lock().unwrap().push(tag);
        }
    }

    #[test]
    #[hardwon("#9755: removing a temporary trace listener erased statement attribution")]
    fn tags_and_listener_detach_preserve_attribution() {
        let bare = Connection::open_in_memory().unwrap();
        assert_eq!(connection_tag(&bare), None);
        let first = Connection::open_in_memory().unwrap();
        let second = Connection::open_in_memory().unwrap();
        install(&first, ConnectionRole::Ephemeral);
        install(&second, ConnectionRole::Ephemeral);
        let first_tag = connection_tag(&first).unwrap();
        let second_tag = connection_tag(&second).unwrap();
        assert_ne!(first_tag, second_tag);
        install(&first, ConnectionRole::Reader);
        assert_eq!(connection_tag(&first), Some(first_tag));
        let seen = Arc::new(Seen(Mutex::new(Vec::new())));
        let _frame = attribution::enter_frame(seen.clone());
        let events = Arc::new(Mutex::new(0));
        let count = events.clone();
        let listener = attach_listener(&first, Arc::new(move |_| *count.lock().unwrap() += 1));
        first.execute_batch("SELECT 1").unwrap();
        drop(listener);
        let before = *events.lock().unwrap();
        first.execute_batch("SELECT 2").unwrap();
        assert_eq!(*events.lock().unwrap(), before);
        assert_eq!(*seen.0.lock().unwrap(), [first_tag, first_tag]);
        // SAFETY: the connection remains live until close returns.
        let address = unsafe { first.handle() } as usize;
        first.close().unwrap();
        assert!(!tags().lock().unwrap().contains_key(&address));
    }

    #[test]
    #[hardwon("#9755: a detached guard could remove a reused connection listener")]
    fn guard_survives_close_and_detaches_while_connection_is_idle() {
        let conn = Connection::open_in_memory().unwrap();
        let first = attach_listener(&conn, Arc::new(|_| {}));
        let hit = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Arc::clone(&hit);
        let second = attach_listener(
            &conn,
            Arc::new(move |event| {
                if matches!(event, ListenerEvent::Statement { .. }) {
                    capture.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }),
        );
        // Simulate check-in: the guard owns only the tag while the connection
        // waits in a pool, and detaching must not remove the second listener.
        let mut pool = vec![conn];
        drop(first);
        let conn = pool.pop().unwrap();
        conn.query_row("SELECT 1", [], |row| row.get::<_, i32>(0))
            .unwrap();
        assert_eq!(hit.load(std::sync::atomic::Ordering::Relaxed), 1);
        let before = ROW_DISPATCHES.with(Cell::get);
        drop(second);
        conn.query_row("SELECT 2", [], |row| row.get::<_, i32>(0))
            .unwrap();
        assert_eq!(ROW_DISPATCHES.with(Cell::get), before);
        let after_close = attach_listener(&conn, Arc::new(|_| {}));
        conn.close().unwrap();
        drop(after_close);
    }

    #[test]
    #[hardwon("#9755: a listener panic crossed SQLite's C callback")]
    fn panicking_listener_does_not_abort_or_hide_the_event() {
        let conn = Connection::open_in_memory().unwrap();
        let lost = attribution::lost_statements();
        let panics = attach_listener(
            &conn,
            Arc::new(|event| {
                if matches!(event, ListenerEvent::Statement { .. }) {
                    panic!("listener");
                }
            }),
        );
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = seen.clone();
        let _second = attach_listener(
            &conn,
            Arc::new(move |event| {
                if matches!(event, ListenerEvent::Statement { .. }) {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }),
        );
        conn.execute_batch("SELECT 1").unwrap();
        // The other listener saw the statement, and attribution lost nothing.
        assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(attribution::lost_statements(), lost);
        drop(panics);
        conn.execute_batch("SELECT 2").unwrap();
        assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    #[hardwon("#9755: a panic in attribution lost a statement without refusing its frame")]
    fn panicking_attribution_observer_marks_the_frame_lost() {
        struct Panics;
        impl attribution::StatementObserver for Panics {
            fn statement(&self, _: &str) {
                panic!("observer");
            }
        }
        struct Lost(std::sync::atomic::AtomicBool);
        impl AttributionFrame for Lost {
            fn mark_unattributed(&self, _: &str, _: Option<&'static str>, _: ConnectionTag) {}
            fn mark_lost(&self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let conn = Connection::open_in_memory().unwrap();
        install(&conn, ConnectionRole::Ephemeral);
        let frame = Arc::new(Lost(std::sync::atomic::AtomicBool::new(false)));
        let _frame = attribution::enter_frame(frame.clone());
        let _observer = attribution::observe_statements(Arc::new(Panics));
        conn.execute_batch("SELECT 1").unwrap();
        assert!(frame.0.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    #[hardwon("#12610: trigger profiling retained unmatched outer SQL buffers across requests")]
    fn profile_trigger_events_do_not_retain_outer_sql() {
        const CHILD: &str = "BIFROST_SQL_TRIGGER_MEMORY_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cache_db::sql_profile::tests::profile_trigger_events_do_not_retain_outer_sql",
                    "--test-threads",
                    "1",
                ])
                .env(CHILD, "1")
                .env_remove(PROFILE_PATH_ENV)
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture failed: {output:?}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(
            TEST_PROFILE
                .set(Profile::new(dir.path().join("sql.jsonl")))
                .is_ok()
        );
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t(v); CREATE TABLE audit(v);
            CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO audit VALUES(new.v); END;
            CREATE TRIGGER audit_tr AFTER INSERT ON audit BEGIN SELECT new.v; END;",
        )
        .unwrap();
        install(&conn, ConnectionRole::Ephemeral);
        let sql = format!("INSERT INTO t VALUES(?1) /*{}*/", "x".repeat(65536));
        for value in 0..10 {
            conn.execute(&sql, [value]).unwrap();
        }
        ACTIVE_STATEMENTS.with(|active| {
            let active = active.borrow();
            let bytes = active.capacity() * std::mem::size_of::<ActiveStatement>();
            assert!(
                active.is_empty(),
                "unmatched active statements={}, retained frame capacity bytes={bytes}",
                active.len()
            );
        });
        // A primary statement can itself begin with a comment. Distinguish
        // executions by SQLite's pointer, not by an event-text prefix.
        let commented = "-- ordinary SQL comment\nSELECT count(*) FROM audit";
        assert_eq!(
            conn.query_row(commented, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            10
        );
        let aggregate = profile().unwrap().aggregate.lock().unwrap();
        assert_eq!(
            aggregate.by_role[ConnectionRole::Ephemeral as usize][commented].rows,
            1
        );
    }

    #[test]
    #[hardwon("#9755: trigger callbacks were reported as repeated outer statements")]
    fn trigger_statement_listener_uses_event_sql() {
        let conn = Connection::open_in_memory().unwrap();
        install(&conn, ConnectionRole::Ephemeral);
        conn.execute_batch(
            "CREATE TABLE t(v); CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT v FROM t; END;",
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let _listener = attach_listener(
            &conn,
            Arc::new(move |event| {
                if let ListenerEvent::Statement { sql: Some(sql), .. } = event {
                    sink.lock().unwrap().push(sql.to_owned());
                }
            }),
        );
        let frame = Arc::new(Seen(Mutex::new(Vec::new())));
        let _frame = attribution::enter_frame(frame.clone());
        conn.execute_batch("INSERT INTO t VALUES (1)").unwrap();
        let statements = seen.lock().unwrap();
        assert!(
            statements
                .iter()
                .any(|sql| sql == "INSERT INTO t VALUES (1)")
        );
        assert!(statements.iter().any(|sql| sql.starts_with("--")));
        assert!(
            frame
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|tag| *tag == connection_tag(&conn).unwrap())
        );
    }

    #[test]
    fn only_core_installs_sqlite_trace() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for base in ["crates", "tests"] {
            let mut pending = vec![root.join(base)];
            while let Some(path) = pending.pop() {
                for entry in std::fs::read_dir(path).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        if path.file_name().unwrap() != "target" {
                            pending.push(path);
                        }
                        continue;
                    }
                    if path.extension().is_none_or(|ext| ext != "rs")
                        || path.ends_with("crates/bifrost-core/src/cache_db/sql_profile.rs")
                    {
                        continue;
                    }
                    let source = std::fs::read_to_string(&path).unwrap();
                    for pattern in [
                        "sqlite3_trace_v2",
                        ".trace_v2(",
                        ".trace(Some",
                        ".profile(Some",
                    ] {
                        assert!(
                            !source.contains(pattern),
                            "{} contains {pattern}",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[hardwon("#9755: CLOSE trace before SQLITE_BUSY could discard a live connection tag")]
    fn refused_close_keeps_tag_and_context() {
        let conn = Connection::open_in_memory().unwrap();
        install(&conn, ConnectionRole::Ephemeral);
        let tag = connection_tag(&conn).unwrap();
        let sql = c"SELECT 1";
        let mut stmt = std::ptr::null_mut();
        // SAFETY: conn is live; the raw statement is finalized before retrying close.
        let address = unsafe {
            let db = conn.handle();
            assert_eq!(
                ffi::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut()),
                ffi::SQLITE_OK
            );
            db as usize
        };
        let (conn, _) = conn
            .close()
            .expect_err("unfinalized statement must refuse close");
        assert_eq!(connection_tag(&conn), Some(tag));
        // SAFETY: stmt belongs to the still-live connection.
        unsafe {
            assert_eq!(ffi::sqlite3_finalize(stmt), ffi::SQLITE_OK);
        }
        conn.close().unwrap();
        assert!(!tags().lock().unwrap().contains_key(&address));
    }

    #[test]
    fn request_record_carries_counter_deltas_only_when_counters_are_on() {
        // The profile and the counter switch are process-global; run in a child.
        const CHILD: &str = "BIFROST_SQL_COUNTERS_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cache_db::sql_profile::tests::request_record_carries_counter_deltas_only_when_counters_are_on"])
                .env(CHILD, "1")
                .env_remove(PROFILE_PATH_ENV)
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture failed: {output:?}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("sql.jsonl");
        assert!(TEST_PROFILE.set(Profile::new(dump_path.clone())).is_ok());
        let count = |n: u64| crate::profile_count!("test.counter", n);
        // Off: counted events are dropped and the field is omitted.
        drop({
            let scope = request_scope("off");
            count(5);
            scope
        });
        crate::profiling::FORCE_COUNTERS.store(true, std::sync::atomic::Ordering::Relaxed);
        // Events before the scope opens are not part of its delta.
        count(7);
        drop({
            let scope = request_scope("on");
            count(2);
            count(1);
            scope
        });
        drop(request_scope("quiet"));
        let requests: Vec<serde_json::Value> =
            std::fs::read_to_string(dump_path.with_extension("requests.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].get("counters").is_none(), "{}", requests[1]);
        assert_eq!(
            requests[2]["counters"],
            serde_json::json!({"test.counter": 3})
        );
        assert_eq!(requests[3]["counters"], serde_json::json!({}));
    }

    #[test]
    #[hardwon(
        "#13223: a request's end counter snapshot was taken after its lock was released, so events in the gap appeared in two records"
    )]
    fn request_counter_deltas_exclude_events_after_the_request_closed() {
        const CHILD: &str = "BIFROST_SQL_COUNTERS_GAP_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cache_db::sql_profile::tests::request_counter_deltas_exclude_events_after_the_request_closed"])
                .env(CHILD, "1")
                .env_remove(PROFILE_PATH_ENV)
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture failed: {output:?}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("sql.jsonl");
        assert!(TEST_PROFILE.set(Profile::new(dump_path.clone())).is_ok());
        crate::profiling::FORCE_COUNTERS.store(true, std::sync::atomic::Ordering::Relaxed);
        // Hold request "first" after its lock is released and before it renders.
        let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let gate = std::sync::Mutex::new((paused_tx, resume_rx));
        assert!(
            TEST_FINISH_HOOK
                .set(Box::new(move |tool| {
                    if tool == "first" {
                        let gate = gate.lock().unwrap();
                        gate.0.send(()).unwrap();
                        gate.1.recv().unwrap();
                    }
                }))
                .is_ok()
        );
        let first = std::thread::spawn(|| {
            let request = request_scope("first");
            crate::profile_count!("test.gap", 1);
            drop(request);
        });
        paused_rx.recv().unwrap();
        let second = request_scope("second");
        assert!(second.counted, "second must own its request");
        crate::profile_count!("test.gap", 2);
        drop(second);
        resume_tx.send(()).unwrap();
        first.join().unwrap();
        let requests: Vec<serde_json::Value> =
            std::fs::read_to_string(dump_path.with_extension("requests.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        let find = |tool: &str| {
            requests
                .iter()
                .find(|row| row["tool"] == tool)
                .unwrap_or_else(|| panic!("no record for {tool}: {requests:?}"))
        };
        assert_eq!(
            find("first")["counters"],
            serde_json::json!({"test.gap": 1})
        );
        assert_eq!(
            find("second")["counters"],
            serde_json::json!({"test.gap": 2})
        );
        assert_eq!(find("first")["overlapped"], false);
        assert_eq!(find("second")["overlapped"], false);
    }

    #[test]
    #[hardwon("#12067: internal schema rows rendered as statements with empty SQL")]
    fn profile_internal_rows_reconcile_with_requests_and_totals() {
        // The collector and request scope are process-global. Isolate the fixture
        // from concurrently running tests that also install the dispatcher.
        const CHILD: &str = "BIFROST_SQL_INTERNAL_ROWS_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cache_db::sql_profile::tests::profile_internal_rows_reconcile_with_requests_and_totals", "--test-threads", "8"])
                .env(CHILD, "1")
                .env_remove(PROFILE_PATH_ENV)
                .output().unwrap();
            assert!(output.status.success(), "fixture failed: {output:?}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("existing.sqlite");
        Connection::open(&db)
            .unwrap()
            .execute_batch(
                "CREATE TABLE original(value); INSERT INTO original VALUES(1),(2); ANALYZE;",
            )
            .unwrap();
        let dump_path = dir.path().join("sql.jsonl");
        assert!(TEST_PROFILE.set(Profile::new(dump_path.clone())).is_ok());
        let mut expected_by_role = [0_u64; ConnectionRole::ALL.len()];
        let mut expected_internal_by_role = [0_u64; ConnectionRole::ALL.len()];
        for role in [
            ConnectionRole::Writer,
            ConnectionRole::Reader,
            ConnectionRole::SessionReader,
        ] {
            let before = totals_with_rows().unwrap().1;
            let scope = request_scope(role.as_str());
            let conn = Connection::open(&db).unwrap();
            install(&conn, role);
            // Opening does not read the existing schema until preparation.
            let rows: i64 = conn
                .query_row("SELECT count(*) FROM original", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 2);
            conn.execute_batch("ANALYZE;").unwrap();
            conn.execute_batch("CREATE TABLE added(value);").unwrap();
            conn.execute_batch("DROP TABLE added;").unwrap();
            drop(conn);
            drop(scope);
            expected_by_role[role as usize] = totals_with_rows().unwrap().1 - before;
        }
        let requests: Vec<serde_json::Value> =
            std::fs::read_to_string(dump_path.with_extension("requests.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        assert_eq!(requests[0], profile_header());
        assert_eq!(requests.len(), 4);
        for request in &requests[1..] {
            let role = ConnectionRole::ALL
                .iter()
                .find(|role| role.as_str() == request["tool"].as_str().unwrap())
                .unwrap();
            let statements = request["statements"].as_array().unwrap();
            assert!(statements.iter().all(|row| row["kind"] == "statement"
                && !row["sql"].as_str().unwrap().is_empty()
                && row["role"] == role.as_str()));
            let internal = request["sqlite_internal_rows"].as_array().unwrap();
            assert_eq!(internal.len(), 1);
            let row = &internal[0];
            assert_eq!(row["role"], role.as_str());
            assert_eq!(row["kind"], "sqlite_internal_rows");
            assert_eq!(row["reason"], "sqlite_schema_or_statistics_statement");
            assert_eq!(row.as_object().unwrap().len(), 4);
            let internal_count = row["decoded_rows"].as_u64().unwrap();
            assert!(internal_count > 0);
            expected_internal_by_role[*role as usize] = internal_count;
            let statement_count = statements
                .iter()
                .map(|row| row["decoded_rows"].as_u64().unwrap())
                .sum::<u64>();
            assert_eq!(
                statement_count + internal_count,
                expected_by_role[*role as usize],
                "request partition: {request}"
            );
            // Nested internal rows remain attributed to the active application
            // statement's execution rows, independently of the ROW partition.
            let create = statements
                .iter()
                .find(|row| row["sql"] == "CREATE TABLE added(value);")
                .unwrap();
            assert!(create["rows"].as_u64().unwrap() > create["decoded_rows"].as_u64().unwrap());
        }
        flush();
        let dump: Vec<serde_json::Value> = std::fs::read_to_string(dump_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(dump[0], profile_header());
        assert!(
            dump.iter()
                .filter(|row| row["kind"] == "statement")
                .all(|row| !row["sql"].as_str().unwrap().is_empty())
        );
        let mut actual_by_role = [0_u64; ConnectionRole::ALL.len()];
        for row in &dump {
            if row["kind"] == "statement" || row["kind"] == "sqlite_internal_rows" {
                let role = ConnectionRole::ALL
                    .iter()
                    .find(|role| row["role"] == role.as_str())
                    .unwrap();
                actual_by_role[*role as usize] += row["decoded_rows"].as_u64().unwrap();
                if row["kind"] == "sqlite_internal_rows" {
                    assert_eq!(
                        row,
                        &internal_row_records(&expected_internal_by_role)
                            .into_iter()
                            .find(|entry| entry["role"] == role.as_str())
                            .unwrap()
                    );
                }
            }
        }
        assert_eq!(actual_by_role, expected_by_role);
        assert_eq!(
            actual_by_role.iter().sum::<u64>(),
            totals_with_rows().unwrap().1
        );
        assert_eq!(dump[1]["decoded_rows"], actual_by_role.iter().sum::<u64>());
    }

    /// The hook exists or it does not: a connection opened while
    /// [`PROFILE_PATH_ENV`] is unset carries no hook for the rest of its life,
    /// and one opened afterwards records every execution of its statements.
    /// Both halves are asserted in one process because [`PROFILE`] is
    /// process-global and is written once.
    #[test]
    #[hardwon("#10272: process-global SQL profile rows include independently opened connections")]
    fn profile_records_only_connections_opened_with_the_variable_set() {
        assert!(
            std::env::var_os(PROFILE_PATH_ENV).is_none(),
            "{PROFILE_PATH_ENV} must be unset for this test's first half"
        );
        let dir = tempfile::tempdir().expect("profile test directory");
        let db = dir.path().join(cache_db_file_name());
        let unprofiled = open_unified_connection(&db).expect("store for the profile test");
        let unprofiled_marker: i64 = unprofiled
            .query_row("SELECT 4242", [], |row| row.get(0))
            .expect("unprofiled marker");
        assert_eq!(unprofiled_marker, 4242);

        assert!(
            profile().is_none(),
            "the store opened above must have installed no hook"
        );

        let dump_path = dir.path().join("profile.jsonl");
        assert!(
            TEST_PROFILE.set(Profile::new(dump_path.clone())).is_ok(),
            "the SQL profile was already configured in this process"
        );

        let profiled = open_readonly_connection(&db).expect("reader for the profile test");
        let independent = open_readonly_connection(&db).expect("independent profile reader");
        // These are process-wide samples, so assert only the rows this test
        // must contribute and allow other connections to add more.
        let (_, rows_before, _) = totals_with_rows().expect("profile totals before marker queries");
        for _ in 0..3 {
            let marker: i64 = profiled
                .query_row("SELECT 1717", [], |row| row.get(0))
                .expect("profiled marker");
            assert_eq!(marker, 1717);
        }
        let independent_marker: i64 = independent
            .query_row("SELECT 1919", [], |row| row.get(0))
            .expect("independent profiled marker");
        assert_eq!(independent_marker, 1919);
        for _ in 0..3 {
            let marker: i64 = profiled
                .prepare_cached("SELECT 1818")
                .expect("cached marker")
                .query_row([], |row| row.get(0))
                .expect("cached marker result");
            assert_eq!(marker, 1818);
        }
        let (_, rows_after, _) = totals_with_rows().expect("profile totals after marker queries");
        assert!(
            rows_after - rows_before >= 7,
            "the seven marker queries must contribute at least seven decoded rows: before={rows_before}, after={rows_after}"
        );
        flush();

        let dump = std::fs::read_to_string(&dump_path).expect("profile dump");
        let lines: Vec<serde_json::Value> = dump
            .lines()
            .map(|line| serde_json::from_str(line).expect("profile dump line"))
            .collect();
        assert_eq!(lines[0], profile_header(), "dump lines: {lines:?}");
        assert_eq!(lines[1]["kind"], "header");
        assert!(lines[1]["decoded_rows"].as_u64().is_some());
        let statements: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "statement")
            .collect();
        let statement_rows = statements
            .iter()
            .map(|line| line["decoded_rows"].as_u64().expect("statement row total"))
            .sum::<u64>();
        let overflow_rows = lines
            .iter()
            .find(|line| line["kind"] == "overflow")
            .map_or(0, |line| {
                line["decoded_rows"].as_u64().expect("overflow row total")
            });
        assert_eq!(
            statement_rows
                + overflow_rows
                + lines
                    .iter()
                    .filter(|line| line["kind"] == "sqlite_internal_rows")
                    .map(|line| line["decoded_rows"].as_u64().unwrap())
                    .sum::<u64>(),
            lines[1]["decoded_rows"].as_u64().expect("global row total"),
            "statement row totals partition the global total: {lines:?}"
        );
        assert!(
            !statements
                .iter()
                .any(|line| line["sql"].as_str() == Some("SELECT 4242")),
            "a connection opened before the profile was configured was recorded: {statements:?}"
        );
        let marker: Vec<&&serde_json::Value> = statements
            .iter()
            .filter(|line| line["sql"].as_str() == Some("SELECT 1717"))
            .collect();
        assert_eq!(marker.len(), 1, "dump statements: {statements:?}");
        assert_eq!(marker[0]["first_run_executions"], 3);
        assert_eq!(marker[0]["reused_executions"], 0);
        assert_eq!(marker[0]["decoded_rows"], 3);
        let cached = statements
            .iter()
            .find(|line| line["sql"] == "SELECT 1818")
            .expect("cached statement profile");
        assert_eq!(cached["executions"], 3);
        assert_eq!(cached["decoded_rows"], 3);
        assert_eq!(cached["first_run_executions"], 1);
        assert_eq!(cached["reused_executions"], 2);
        assert_eq!(cached["max_statement_runs"], 3);
        assert_eq!(cached["max_statement_reprepares"], 0);
        let independent_marker = statements
            .iter()
            .find(|line| line["sql"] == "SELECT 1919")
            .expect("independent connection statement profile");
        assert_eq!(independent_marker["executions"], 1);
        assert_eq!(independent_marker["decoded_rows"], 1);
        assert_eq!(
            marker[0]["role"], "reader",
            "dump statements: {statements:?}"
        );
        assert_eq!(
            marker[0]["executions"], 3,
            "dump statements: {statements:?}"
        );
        assert_eq!(
            marker[0]["expanded_sql"].as_str(),
            Some("SELECT 1717"),
            "dump statements: {statements:?}"
        );
    }
}
