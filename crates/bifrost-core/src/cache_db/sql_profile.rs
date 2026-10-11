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
//! variable is read once per process; with it unset, [`install`] installs no
//! hook and a connection behaves exactly as it did before this module existed.
//!
//! The rusqlite callback is a plain function pointer with no context argument,
//! so the aggregate is process-global behind one mutex and the connection's
//! role is baked into the function pointer by [`callback_for`]. One process is
//! one workload: the runner names the output file, and nothing here tags a
//! route.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::trace::{TraceEvent, TraceEventCodes};
use rusqlite::{Connection, StatementStatus};

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
    role: ConnectionRole,
    sql: String,
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
    row_histogram: HashMap<u64, u64>,
    key_histogram: HashMap<u64, u64>,
    repeated_expanded_invocations: u64,
    untracked_expanded_invocations: u64,
}

struct RequestAggregate {
    tool: String,
    started: Instant,
    overlapped: bool,
    statements: HashMap<u64, RequestStatement>,
    seen_bindings: HashSet<(u64, u64)>,
}

impl RequestAggregate {
    fn new(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            started: Instant::now(),
            overlapped: false,
            statements: HashMap::new(),
            seen_bindings: HashSet::new(),
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
        let mut family_hasher = DefaultHasher::new();
        role.hash(&mut family_hasher);
        sql.hash(&mut family_hasher);
        let family = family_hasher.finish();
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let statement = self.statements.entry(family).or_default();
        if statement.role.is_none() {
            statement.role = Some(role);
            statement.sql = sql.to_string();
        }
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
        serde_json::json!({
            "kind": "request",
            "tool": self.tool,
            "wall_ms": self.started.elapsed().as_secs_f64() * 1000.0,
            "overlapped": self.overlapped,
            "expanded_binding_cap": REQUEST_BINDING_CAP,
            "distinct_expanded_bindings": self.seen_bindings.len(),
            "statements": statements,
        })
        .to_string()
    }
}

/// A request-local SQL family profile. Its statement totals and histograms are
/// written beside the process-wide dump as `<profile>.requests.jsonl`.
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

    const fn from_index(index: u8) -> Self {
        Self::ALL[index as usize]
    }

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

struct Aggregate {
    /// One map per role, so a repeat execution finds its entry without
    /// allocating a key.
    by_role: [HashMap<String, Statement>; ConnectionRole::ALL.len()],
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
        {
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
        let request = profile
            .active_request
            .lock()
            .expect("SQL request profile poisoned")
            .take()
            .expect("counted SQL request scope owns an open request");
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

/// Install the profile hook on one analyzer-store connection.
///
/// Called from the single opener in `cache_db`, so no connection can be missed.
pub(crate) fn install(conn: &Connection, role: ConnectionRole) {
    if profile().is_none() {
        return;
    }
    static FLUSHER: Once = Once::new();
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
    conn.trace_v2(
        TraceEventCodes::SQLITE_TRACE_STMT
            | TraceEventCodes::SQLITE_TRACE_PROFILE
            | TraceEventCodes::SQLITE_TRACE_ROW
            | TraceEventCodes::SQLITE_TRACE_CLOSE,
        Some(callback_for(role)),
    );
}

/// A function pointer that carries the role, because the SQLite callback takes
/// none.
fn callback_for(role: ConnectionRole) -> fn(TraceEvent<'_>) {
    match role {
        ConnectionRole::Writer => on_event::<{ ConnectionRole::Writer as u8 }>,
        ConnectionRole::Reader => on_event::<{ ConnectionRole::Reader as u8 }>,
        ConnectionRole::SessionReader => on_event::<{ ConnectionRole::SessionReader as u8 }>,
        ConnectionRole::StreamingReader => on_event::<{ ConnectionRole::StreamingReader as u8 }>,
        ConnectionRole::UpgradeSource => on_event::<{ ConnectionRole::UpgradeSource as u8 }>,
        ConnectionRole::UpgradeTarget => on_event::<{ ConnectionRole::UpgradeTarget as u8 }>,
        ConnectionRole::VersionProbe => on_event::<{ ConnectionRole::VersionProbe as u8 }>,
        ConnectionRole::Cleanup => on_event::<{ ConnectionRole::Cleanup as u8 }>,
        ConnectionRole::Ephemeral => on_event::<{ ConnectionRole::Ephemeral as u8 }>,
    }
}

fn on_event<const ROLE: u8>(event: TraceEvent<'_>) {
    match event {
        TraceEvent::Stmt(statement, _) => {
            let role = ConnectionRole::from_index(ROLE);
            let active = ActiveStatement {
                role,
                sql: statement.sql().into_owned(),
                keys: LOGICAL_KEY_COUNT.with(Cell::get),
                rows: 0,
            };
            ACTIVE_STATEMENTS.with(|current| current.borrow_mut().push(active));
        }
        TraceEvent::Row(statement) => {
            let role = ConnectionRole::from_index(ROLE);
            ACTIVE_STATEMENTS.with(|current| {
                if let Some(active) = current.borrow_mut().last_mut() {
                    active.rows += 1;
                }
            });
            record_decoded_row(role, statement.sql().as_ref());
        }
        TraceEvent::Profile(statement, elapsed) => {
            let role = ConnectionRole::from_index(ROLE);
            let sql = statement.sql();
            let (keys, rows) = ACTIVE_STATEMENTS.with(|current| {
                let mut active = current.borrow_mut();
                active
                    .iter()
                    .rposition(|entry| entry.role == role && entry.sql == sql.as_ref())
                    .map(|index| active.remove(index))
                    .map_or((None, 0), |entry| (entry.keys, entry.rows))
            });
            let expanded = statement.expanded_sql();
            record(
                role,
                sql.as_ref(),
                expanded.clone(),
                elapsed,
                statement.get_status(StatementStatus::Run),
                statement.get_status(StatementStatus::RePrepare),
                rows,
            );
            if let Some(profile) = profile() {
                profile.record_request_statement(
                    role,
                    sql.as_ref(),
                    expanded.as_deref(),
                    elapsed,
                    keys,
                    rows,
                );
            }
        }
        TraceEvent::Close(_) => flush(),
        _ => {}
    }
}

fn record_decoded_row(role: ConnectionRole, sql: &str) {
    let Some(profile) = profile() else {
        return;
    };
    let mut aggregate = profile
        .aggregate
        .lock()
        .expect("SQL profile aggregate poisoned");
    aggregate.decoded_rows = aggregate
        .decoded_rows
        .checked_add(1)
        .expect("SQL profile decoded row count fits u64");
    let index = role as usize;
    if let Some(statement) = aggregate.by_role[index].get_mut(sql) {
        statement.decoded_rows = statement
            .decoded_rows
            .checked_add(1)
            .expect("statement decoded row count fits u64");
    } else if aggregate.distinct < STATEMENT_CAP {
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
    let mut dump = serde_json::json!({
        "kind": "header",
        "pid": std::process::id(),
        "statement_cap": STATEMENT_CAP,
        "expanded_sample_cap_bytes": EXPANDED_SAMPLE_CAP_BYTES,
        "distinct_statements": aggregate.distinct,
        "decoded_rows": aggregate.decoded_rows,
        "flush_interval_ms": FLUSH_INTERVAL.as_millis(),
    })
    .to_string();
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
    use crate::cache_db::{cache_db_file_name, open_readonly_connection, open_unified_connection};

    /// The hook exists or it does not: a connection opened while
    /// [`PROFILE_PATH_ENV`] is unset carries no hook for the rest of its life,
    /// and one opened afterwards records every execution of its statements.
    /// Both halves are asserted in one process because [`PROFILE`] is
    /// process-global and is written once.
    #[test]
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
        let (_, rows_before, _) = totals_with_rows().expect("profile totals before marker queries");
        for _ in 0..3 {
            let marker: i64 = profiled
                .query_row("SELECT 1717", [], |row| row.get(0))
                .expect("profiled marker");
            assert_eq!(marker, 1717);
        }
        for _ in 0..3 {
            let marker: i64 = profiled
                .prepare_cached("SELECT 1818")
                .expect("cached marker")
                .query_row([], |row| row.get(0))
                .expect("cached marker result");
            assert_eq!(marker, 1818);
        }
        let (_, rows_after, _) = totals_with_rows().expect("profile totals after marker queries");
        assert_eq!(rows_after - rows_before, 6);
        flush();

        let dump = std::fs::read_to_string(&dump_path).expect("profile dump");
        let lines: Vec<serde_json::Value> = dump
            .lines()
            .map(|line| serde_json::from_str(line).expect("profile dump line"))
            .collect();
        assert_eq!(lines[0]["kind"], "header", "dump lines: {lines:?}");
        assert!(lines[0]["decoded_rows"].as_u64().is_some());
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
            statement_rows + overflow_rows,
            lines[0]["decoded_rows"].as_u64().expect("global row total"),
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
