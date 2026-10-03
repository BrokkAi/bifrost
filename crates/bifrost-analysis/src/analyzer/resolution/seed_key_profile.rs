//! How often one reference-seed read repeats inside one MCP tool call.
//!
//! The whole-workspace `usage_graph` does not finish inside its bar, and the
//! four per-statement fixes removed the pathological plans without removing the
//! volume: a rooted diagnostic graph over one generated file issued 5,566,351
//! SQL executions and 356,671 scalar reference-seed reads for 30,045 enumerated
//! references, and a bounded debugger trace showed each seed key being read
//! about ten times inside one phase. [`seam_profile`](super::seam_profile)
//! already says how many seed reads a request makes; it does not say how many
//! of them ask the same question again. This module says that, for the whole
//! graph rather than for a bounded sample, before anybody redesigns the demand
//! scheduler around a cache.
//!
//! The instrument is off unless `BIFROST_SEED_KEY_PROFILE` names an output
//! file. The variable is read once per process. With it unset every recording
//! site is one `OnceLock` load against a value the optimizer can hoist, and no
//! request observes any other difference.
//!
//! # The key
//!
//! A read is recorded under the value a reuse would have to match, not under
//! the reference alone:
//!
//! - the runtime [`SemanticId`] of the reference, which carries its mount
//!   ordinal and catalog position, or its interned shared name;
//! - the selection's stage request identity;
//! - the selection's committed stage-content epoch;
//! - the identity of the mounts the request may currently bind into.
//!
//! The first three are what `candidate_coverage_fingerprint` already combines.
//! The fourth is not in that fingerprint, and
//! `.agents/docs/stack-graph-reader-statement-lifetime-2026-09-21.md` records
//! why it has to be in this one: `persisted_reference_seeds` combines ordinary
//! metadata, stage metadata, fragment and local gaps and effective closed
//! reasons, every membership read joins
//! `temp.selected_resolution_scope_mounts`, and a forward Rust request narrows
//! that relation for its own length. Two reads of one reference under two
//! scopes are two different questions.
//!
//! What the key does *not* carry is external freshness. A real cache also has
//! to reject a withdrawn publication and must not answer a cancelled read from
//! a successful result; `read_change_stamp` costs three cached PRAGMA reads, so
//! neither is free. This instrument measures repetition, which is the upper
//! bound on what any cache could save, not the saving itself.
//!
//! # Memory
//!
//! The per-call table holds one entry per distinct key the call reads and is
//! dropped when the call ends, which is the "one query's result for that
//! query's lifetime" shape the heap rules allow: it is not an index that
//! outlives a query and it does not scale with the workspace beyond the one
//! request in flight. [`DISTINCT_KEY_CAP`] bounds it anyway, because the
//! workload this instrument exists for is the one that already exceeded 2 GiB.
//!
//! # Output
//!
//! JSON lines, like the seam profile. One `request` line per MCP tool call, one
//! `progress` line every [`PROGRESS_INTERVAL`] carrying the open call's partial
//! aggregate, and one `totals` line per request end. The warm `usage_graph`
//! workload is killed by `timeout` and never closes its request, so a profile
//! that only wrote at the request boundary would write nothing at all for it.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::hash::HashMap;

use super::batch::{BatchReferenceSeed, ReferenceSeed, SeedReadAuthority};
use super::engine::ResolutionQuery;
use super::model::{ResolutionCompletion, ResolutionIncompleteReason};

/// Names the JSON-lines output file. Unset means no instrument at all.
pub const PROFILE_PATH_ENV: &str = "BIFROST_SEED_KEY_PROFILE";

/// How often the background writer appends the open call's partial aggregate.
///
/// Longer than the seam profile's five seconds because this writer walks the
/// key table under the lock that the seed reads take, and the table can hold a
/// million entries.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

/// Distinct keys the per-call table keeps before it stops growing.
///
/// Unlike the SQL profile's statement cap this is not a property of the code:
/// a whole-workspace graph can read more distinct references than this. The cap
/// is a memory bound, and the dump reports both that it was reached and how
/// many reads landed past it, so a capped line is still an honest lower bound
/// on repetition. At the cap the table is about 2^21 slots of a 32-byte key and
/// an 8-byte count, near 90 MiB.
const DISTINCT_KEY_CAP: usize = 1 << 20;

/// Most-read keys the dump names.
const TOP_KEYS: usize = 20;

/// One reference-seed read, as a reusable result would have to be identified.
///
/// The scope is an index into [`Call::scopes`] rather than its 32 bytes: one
/// call meets a handful of scopes and a million keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SeedKey {
    reference: u64,
    request: u64,
    content_epoch: u64,
    scope: u32,
}

/// Everything one open tool call has read. Dropped when the call ends.
struct Call {
    tool: String,
    started: Instant,
    overlapped: bool,
    keys: HashMap<SeedKey, u64>,
    /// The distinct scope identities this call has met, in first-seen order.
    scopes: Vec<[u8; 32]>,
    reads: u64,
    /// Reads whose key was not in the table when [`DISTINCT_KEY_CAP`] was
    /// already reached. Their repetition is unknown, not zero.
    uncounted_reads: u64,
    batches: u64,
    seeds_returned: u64,
    result_bytes: u64,
    /// The demanded-reference memos this call's operations dropped: how many
    /// there were, the largest entry count one of them reached, and the
    /// largest byte estimate. The memo is what realizes the saving this
    /// instrument measures the upper bound of, so its size belongs beside the
    /// repetition it removes.
    memos: u64,
    memo_entries_max: u64,
    memo_entries_total: u64,
    memo_bytes_max: u64,
    memo_bytes_total: u64,
}

impl Call {
    fn open(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            started: Instant::now(),
            overlapped: false,
            keys: HashMap::default(),
            scopes: Vec::new(),
            reads: 0,
            uncounted_reads: 0,
            batches: 0,
            seeds_returned: 0,
            result_bytes: 0,
            memos: 0,
            memo_entries_max: 0,
            memo_entries_total: 0,
            memo_bytes_max: 0,
            memo_bytes_total: 0,
        }
    }

    /// The index this call knows `scope` by, adding it when it is new.
    ///
    /// A linear scan: a call meets one scope per crate it narrows to, and the
    /// scan is shorter than hashing thirty-two bytes would be.
    fn scope_index(&mut self, scope: [u8; 32]) -> u32 {
        if let Some(index) = self.scopes.iter().position(|known| *known == scope) {
            return u32::try_from(index).expect("a scope index fits u32");
        }
        self.scopes.push(scope);
        u32::try_from(self.scopes.len() - 1).expect("a scope index fits u32")
    }

    fn record(&mut self, key: SeedKey) {
        self.reads += 1;
        if let Some(reads) = self.keys.get_mut(&key) {
            *reads += 1;
            return;
        }
        if self.keys.len() >= DISTINCT_KEY_CAP {
            self.uncounted_reads += 1;
            return;
        }
        self.keys.insert(key, 1);
    }
}

struct Profile {
    started: Instant,
    output: Mutex<std::fs::File>,
    /// The open call, or `None` between calls. A read outside any call is
    /// counted in the process totals and nowhere else.
    call: Mutex<Option<Call>>,
    in_flight: AtomicUsize,
    calls: AtomicU64,
    total_reads: AtomicU64,
    total_seeds: AtomicU64,
    total_result_bytes: AtomicU64,
    reads_outside_a_call: AtomicU64,
}

impl Profile {
    fn open(path: &std::path::Path) -> Option<Self> {
        match std::fs::File::create(path) {
            Ok(output) => Some(Self {
                started: Instant::now(),
                output: Mutex::new(output),
                call: Mutex::new(None),
                in_flight: AtomicUsize::new(0),
                calls: AtomicU64::new(0),
                total_reads: AtomicU64::new(0),
                total_seeds: AtomicU64::new(0),
                total_result_bytes: AtomicU64::new(0),
                reads_outside_a_call: AtomicU64::new(0),
            }),
            Err(error) => {
                eprintln!(
                    "Bifrost seed key profile could not create {}: {error}",
                    path.display()
                );
                None
            }
        }
    }

    fn write_line(&self, line: &str) {
        let mut output = self
            .output
            .lock()
            .expect("seed key profile output poisoned");
        if let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush()) {
            eprintln!("Bifrost seed key profile could not write a line: {error}");
        }
    }
}

static PROFILE: OnceLock<Option<Profile>> = OnceLock::new();

/// The test seam, for the same reason the SQL profile has one: the environment
/// is read once and its answer is kept, so a test that wants the instrument on
/// cannot get there through the variable.
#[cfg(test)]
static TEST_PROFILE: OnceLock<Profile> = OnceLock::new();

/// The process's profile, or `None` when [`PROFILE_PATH_ENV`] is unset. The
/// environment is read exactly once, on the first seed read or call scope.
fn profile() -> Option<&'static Profile> {
    #[cfg(test)]
    if let Some(profile) = TEST_PROFILE.get() {
        return Some(profile);
    }
    PROFILE
        .get_or_init(|| {
            let path = PathBuf::from(std::env::var_os(PROFILE_PATH_ENV)?);
            let profile = Profile::open(&path)?;
            profile.write_line(&header_line());
            spawn_progress_writer();
            Some(profile)
        })
        .as_ref()
}

/// Turn the instrument on in this process, writing to `path`.
#[cfg(test)]
pub(crate) fn install_for_test(path: &std::path::Path) {
    let profile = Profile::open(path).expect("the seed key profile test output opens");
    profile.write_line(&header_line());
    assert!(
        TEST_PROFILE.set(profile).is_ok(),
        "the seed key profile was already configured in this process"
    );
}

/// Whether the instrument is on in this process.
pub fn enabled() -> bool {
    profile().is_some()
}

fn header_line() -> String {
    serde_json::json!({
        "kind": "header",
        "pid": std::process::id(),
        "distinct_key_cap": DISTINCT_KEY_CAP,
        "top_keys": TOP_KEYS,
        "progress_interval_ms": PROGRESS_INTERVAL.as_millis(),
        "key_components": ["reference", "request", "content_epoch", "scope"],
    })
    .to_string()
}

fn spawn_progress_writer() {
    let spawned = std::thread::Builder::new()
        .name("bifrost-seed-key-profile".to_string())
        .spawn(|| {
            loop {
                std::thread::sleep(PROGRESS_INTERVAL);
                write_progress();
            }
        });
    if let Err(error) = spawned {
        eprintln!("Bifrost seed key profile has no background writer: {error}");
    }
}

/// Append the open call's partial aggregate. With no call open, or with the
/// variable unset, it does nothing.
pub fn write_progress() {
    let Some(profile) = profile() else {
        return;
    };
    let line = {
        let call = profile.call.lock().expect("seed key profile call poisoned");
        let Some(call) = call.as_ref() else {
            return;
        };
        call_object("progress", call).to_string()
    };
    profile.write_line(&line);
}

/// Append a `totals` line now. With the variable unset it does nothing.
pub fn write_totals() {
    let Some(profile) = profile() else {
        return;
    };
    let line = serde_json::json!({
        "kind": "totals",
        "uptime_ms": profile.started.elapsed().as_millis(),
        "calls": profile.calls.load(Ordering::Relaxed),
        "seed_reads": profile.total_reads.load(Ordering::Relaxed),
        "seeds_returned": profile.total_seeds.load(Ordering::Relaxed),
        "result_bytes": profile.total_result_bytes.load(Ordering::Relaxed),
        "reads_outside_a_call": profile.reads_outside_a_call.load(Ordering::Relaxed),
    })
    .to_string();
    profile.write_line(&line);
}

/// The aggregate of one call, as the `request` and `progress` lines carry it.
///
/// The three derived collections -- the histogram, the top keys and the
/// references read under more than one authority -- are all computed here in
/// one pass over the table, so nothing is carried per read that the report can
/// derive at the end.
fn call_object(kind: &str, call: &Call) -> serde_json::Value {
    let mut histogram = [0_u64; 6];
    // A partial selection rather than a sort of the whole table, which can hold
    // a million entries and is walked again on every progress tick. The floor
    // is the twentieth count, so a key below it costs one comparison.
    let mut top: Vec<(SeedKey, u64)> = Vec::with_capacity(TOP_KEYS + 1);
    let mut floor = 0_u64;
    // How many distinct keys each distinct reference has. A reference with more
    // than one is one a cache keyed on the reference alone would serve wrongly,
    // because its reads ran under more than one request, epoch or scope. The
    // table is bounded by the one it walks and is dropped with this line.
    let mut keys_per_reference: HashMap<u64, u32> = HashMap::default();
    for (key, reads) in &call.keys {
        histogram[bucket(*reads)] += 1;
        if top.len() < TOP_KEYS || *reads > floor {
            top.push((*key, *reads));
            top.sort_unstable_by(|left, right| {
                right
                    .1
                    .cmp(&left.1)
                    .then_with(|| left.0.reference.cmp(&right.0.reference))
            });
            top.truncate(TOP_KEYS);
            floor = top.last().map_or(0, |(_, reads)| *reads);
        }
        *keys_per_reference.entry(key.reference).or_insert(0) += 1;
    }
    let spanning = keys_per_reference
        .values()
        .filter(|keys| **keys > 1)
        .count();
    let top = top
        .into_iter()
        .map(|(key, reads)| {
            serde_json::json!({
                "reference": key.reference,
                "request": key.request,
                "content_epoch": key.content_epoch,
                "scope": hex(&call.scopes[key.scope as usize]),
                "reads": reads,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "kind": kind,
        "tool": call.tool,
        "wall_ms": call.started.elapsed().as_secs_f64() * 1000.0,
        "overlapped": call.overlapped,
        "seed_reads": call.reads,
        "seed_batches": call.batches,
        "seeds_returned": call.seeds_returned,
        "result_bytes": call.result_bytes,
        "demanded_reference_memos": call.memos,
        "demanded_reference_memo_entries_max": call.memo_entries_max,
        "demanded_reference_memo_entries_total": call.memo_entries_total,
        "demanded_reference_memo_bytes_max": call.memo_bytes_max,
        "demanded_reference_memo_bytes_total": call.memo_bytes_total,
        "distinct_keys": call.keys.len(),
        "distinct_references": keys_per_reference.len(),
        "references_under_more_than_one_authority": spanning,
        "uncounted_reads": call.uncounted_reads,
        "distinct_key_cap_reached": call.keys.len() >= DISTINCT_KEY_CAP,
        "reads_per_key": {
            "1": histogram[0],
            "2": histogram[1],
            "3_4": histogram[2],
            "5_8": histogram[3],
            "9_16": histogram[4],
            "17_plus": histogram[5],
        },
        "scopes": call.scopes.iter().map(hex).collect::<Vec<_>>(),
        "top_keys": top,
    })
}

/// Which reads-per-key bucket a count falls in: 1, 2, 3-4, 5-8, 9-16, 17+.
const fn bucket(reads: u64) -> usize {
    match reads {
        0 => panic!("a recorded key has at least one read"),
        1 => 0,
        2 => 1,
        3..=4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        _ => 5,
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

/// The bytes one seed result occupies, near enough for a cache-size decision.
///
/// The seed's own fields are fixed width. Its completion is not: a completion
/// carries a reason list, and a factored one shares its base through an `Arc`
/// with every other answer of the same operation. This charges every seed for
/// its whole effective reason list, so the number is an upper bound on what a
/// cache holding these results would retain, and a large gap between it and the
/// entry count is exactly the "completion arrays make an entry cap a poor
/// memory estimate" finding it exists to quantify.
fn approximate_seed_bytes(seed: &ReferenceSeed) -> u64 {
    let reasons = match seed.completion() {
        ResolutionCompletion::Complete => 0,
        ResolutionCompletion::Incomplete(reasons) => reasons.len(),
    };
    u64::try_from(size_of::<ReferenceSeed>() + reasons * size_of::<ResolutionIncompleteReason>())
        .expect("an approximate seed size fits u64")
}

/// Record one reader call's worth of reference-seed reads.
///
/// One read per query, whatever the read returned: an answered query, a query
/// with no seed and a query the read cancelled before reaching all cost the
/// same SQL, and the scheduler asked all of them. The bytes come from the rows,
/// which are empty on a cancelled read.
pub(crate) fn record_seed_reads(
    authority: SeedReadAuthority,
    queries: &[ResolutionQuery],
    rows: &[BatchReferenceSeed],
) {
    let Some(profile) = profile() else {
        return;
    };
    let seeds = rows.iter().filter_map(BatchReferenceSeed::seed);
    let (returned, bytes) = seeds.fold((0_u64, 0_u64), |(returned, bytes), seed| {
        (returned + 1, bytes + approximate_seed_bytes(seed))
    });
    let reads = u64::try_from(queries.len()).expect("a batch length fits u64");
    profile.total_reads.fetch_add(reads, Ordering::Relaxed);
    profile.total_seeds.fetch_add(returned, Ordering::Relaxed);
    profile
        .total_result_bytes
        .fetch_add(bytes, Ordering::Relaxed);
    let mut open = profile.call.lock().expect("seed key profile call poisoned");
    let Some(call) = open.as_mut() else {
        profile
            .reads_outside_a_call
            .fetch_add(reads, Ordering::Relaxed);
        return;
    };
    let scope = call.scope_index(authority.scope);
    call.batches += 1;
    call.seeds_returned += returned;
    call.result_bytes += bytes;
    for query in queries {
        call.record(SeedKey {
            reference: query.reference().get(),
            request: authority.request,
            content_epoch: authority.content_epoch,
            scope,
        });
    }
}

/// One operation's demanded-reference memo, as it was when it was dropped.
///
/// Called from `ForwardCandidateArtifactCache`'s `Drop`, which is the only
/// point that knows the size the memo reached. A graph request drops one per
/// crate stage, so the call's totals describe every operation it built and its
/// maxima describe the largest single one.
pub(crate) fn record_demanded_reference_memo(entries: usize, bytes: usize) {
    let Some(profile) = profile() else {
        return;
    };
    let entries = u64::try_from(entries).expect("a memo entry count fits u64");
    let bytes = u64::try_from(bytes).expect("a memo byte estimate fits u64");
    let mut open = profile.call.lock().expect("seed key profile call poisoned");
    let Some(call) = open.as_mut() else {
        return;
    };
    call.memos += 1;
    call.memo_entries_total += entries;
    call.memo_bytes_total += bytes;
    call.memo_entries_max = call.memo_entries_max.max(entries);
    call.memo_bytes_max = call.memo_bytes_max.max(bytes);
}

/// One tool call's boundary. Its `Drop` writes the call's line and drops the
/// call's table.
///
/// It is a scope and not a pair of calls so that an early return, a `?` or a
/// panic in the tool still closes the call and frees the table.
pub struct CallScope {
    open: bool,
}

/// Open a call boundary for one MCP tool call. A no-op when the instrument is
/// off.
///
/// An overlapping call is recorded as such and shares the open table, exactly
/// as the seam profile's overlapping request shares its counters: two graphs at
/// once is not what the warm workload does, and the line says when it happened.
pub fn call_scope(tool: &str) -> CallScope {
    let Some(profile) = profile() else {
        return CallScope { open: false };
    };
    let overlapped = profile.in_flight.fetch_add(1, Ordering::Relaxed) > 0;
    let mut open = profile.call.lock().expect("seed key profile call poisoned");
    match open.as_mut() {
        Some(call) => call.overlapped = true,
        None => {
            // Only the last scope to close takes the call, so an in-flight
            // scope always has one.
            assert!(!overlapped, "an in-flight call scope keeps its call open");
            *open = Some(Call::open(tool));
        }
    }
    CallScope { open: true }
}

impl Drop for CallScope {
    fn drop(&mut self) {
        if !self.open {
            return;
        }
        let profile = profile().expect("an open call scope implies a profile");
        let last = profile.in_flight.fetch_sub(1, Ordering::Relaxed) == 1;
        if !last {
            return;
        }
        let line = {
            let mut open = profile.call.lock().expect("seed key profile call poisoned");
            let call = open.take().expect("an open call scope implies a call");
            call_object("request", &call).to_string()
        };
        profile.calls.fetch_add(1, Ordering::Relaxed);
        profile.write_line(&line);
        write_totals();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Whether the instrument is off without its variable is not asserted here.
    // [`TEST_PROFILE`] is process-global and
    // `resolution_stage::lexical_reader_tests` turns it on, so a test in this
    // binary that asserted the off state would depend on which test ran first.
    // That test owns both halves instead.

    #[test]
    fn reads_per_key_buckets_cover_every_count() {
        assert_eq!(
            (1..=20).map(bucket).collect::<Vec<_>>(),
            vec![0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5]
        );
        assert_eq!(bucket(u64::MAX), 5);
    }
}
