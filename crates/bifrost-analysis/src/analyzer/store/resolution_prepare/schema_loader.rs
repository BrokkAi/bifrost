//! Lane LD: load a corpus into the milestone 5 draft schema and measure it.
//!
//! This module is a measurement harness, not product code. It changes nothing
//! the engine reads: it parses a corpus's Rust files with the adapter
//! `produce_interior` uses, lowers each file with
//! `lower_resolution_facts_with_identity_catalog` exactly as
//! `prepare_parsed_blob_at_generations` does, assigns the same dense local keys
//! through `ResolutionLocalKeys`, and writes the rows into a scratch SQLite
//! database under the DDL in `../resolution_draft_schema.sql`.
//!
//! It is a child module of `resolution_prepare` so that it can reuse
//! `ResolutionLocalKeys` instead of assigning a second set of keys.
//!
//! Run it with, for example:
//!
//! ```text
//! BIFROST_LD_CORPUS=/mnt/optane/sg-compare/native/tract \
//! BIFROST_LD_DIR=/mnt/optane/lane-receipts/bifrost-sg-tr/ld/db \
//! cargo nextest run --release -p brokk-bifrost-analysis --lib --no-default-features \
//!   --run-ignored only -E 'test(draft_schema_loader)' --success-output immediate
//! ```
//!
//! Environment:
//!
//! * `BIFROST_LD_CORPUS`: the corpus root (required).
//! * `BIFROST_LD_DIR`: where the scratch databases are written (required).
//! * `BIFROST_LD_PASSES`: comma-separated pass names, default all of
//!   `draft,txn64,batch16,txn64batch16,fk,enums`.
//! * `BIFROST_LD_SEEKS`: probes per seek shape, default 100000.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_BINDING_PROJECTION_KINDS, ALL_DECLARATION_TYPE_ROLES, ALL_INTRINSIC_TYPE_KINDS,
    ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS, ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS,
    ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS, ALL_RESOLUTION_ENGINE_RULE_KINDS,
    ALL_RESOLUTION_GAP_KINDS, ALL_RESOLUTION_MEMBER_ACCESSES, ALL_RESOLUTION_MEMBER_KINDS,
    ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES, ALL_RESOLUTION_NAMESPACES,
    ALL_RESOLUTION_SITE_KINDS, ALL_RESOLUTION_SUPERTYPE_KINDS, ALL_RESOLUTION_TYPE_SLOT_ROLES,
    ALL_RESOLUTION_TYPE_TRANSFER_KINDS, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BOUNDARY_STATUSES, ALL_PRECEDENCE_TIERS, ALL_REJECTION_REASONS,
    ALL_RESOLUTION_COMPLETION_REASON_KINDS, ALL_RESOLUTION_GAP_ORIGIN_KINDS, CandidateOutcome,
};
use rusqlite::types::Value;
use rusqlite::{Connection, params_from_iter};

use super::ResolutionLocalKeys;
use crate::CancellationToken;
use crate::analyzer::ProjectFile;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, LoweredCandidateDirection,
    LoweredCoverageGap, LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole,
    LoweringCoverageFrontier, PartialPath, ResolutionCompletion, ResolutionIdentityCatalog,
    ResolutionIncompleteReason, ResolutionSemanticIdentitySpace, SemanticId, StackVariableId,
    TypeTransferValueTransform, WitnessStep, lower_resolution_facts_with_identity_catalog,
};
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::store::resolution::resolution_bundle_epoch;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::hash::{HashMap, HashSet};

const DRAFT_SCHEMA: &str = include_str!("../resolution_draft_schema.sql");

/// The store's page size, so the scratch databases pack rows as it does.
const PAGE_SIZE: u32 = 32_768;

// ---------------------------------------------------------------------------
// Vocabulary codes
// ---------------------------------------------------------------------------

/// The integer code of one enumeration value: its declaration position in the
/// `labelled_enum!` vocabulary that owns it. One rule for every enumeration, so
/// nothing in this loader invents a numbering of its own.
fn code<T: PartialEq + Copy>(all: &[T], value: T) -> i64 {
    let index = all
        .iter()
        .position(|candidate| *candidate == value)
        .expect("an enumeration value belongs to its own vocabulary");
    i64::try_from(index).expect("a vocabulary position fits an integer")
}

/// The loader measures one Rust corpus; a second language would extend this.
fn language_code(label: &str) -> i64 {
    assert_eq!(label, "rust", "the draft loader measures a Rust corpus");
    0
}

// ---------------------------------------------------------------------------
// JSON bodies
// ---------------------------------------------------------------------------

/// Append a separator unless this is the first value of the document or of the
/// array that was just opened.
fn sep(out: &mut String) {
    if !out.is_empty() && !out.ends_with('[') {
        out.push(',');
    }
}

fn push_int(out: &mut String, value: i64) {
    sep(out);
    out.push_str(&value.to_string());
}

fn push_option(out: &mut String, value: Option<i64>) {
    match value {
        Some(value) => push_int(out, value),
        None => {
            sep(out);
            out.push_str("null");
        }
    }
}

fn open(out: &mut String) {
    sep(out);
    out.push('[');
}

fn close(out: &mut String) {
    out.push(']');
}

// ---------------------------------------------------------------------------
// Shared-name interning
// ---------------------------------------------------------------------------

/// The store-wide `resolution_identities` table as one map from a 32-byte
/// digest to its integer id. This is the only structure the loader holds for
/// the whole load; its size is reported.
struct Interner {
    by_digest: HashMap<[u8; 32], i64>,
    has_recipe: Vec<bool>,
    late_recipes: u64,
    without_recipe: u64,
}

impl Interner {
    fn new() -> Self {
        Self {
            by_digest: HashMap::default(),
            has_recipe: Vec::new(),
            late_recipes: 0,
            without_recipe: 0,
        }
    }

    fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// The id of one shared name, and the row to write when this call interned
    /// it. A caller that only needs ids (the enumeration pass) drops the row.
    fn intern(
        &mut self,
        identities: &ResolutionIdentityCatalog,
        semantic: SemanticId,
    ) -> (i64, Option<Vec<Value>>) {
        let identity = identities
            .semantic_identity(semantic)
            .expect("an interned semantic is in its blob's catalog");
        let name = identity
            .shared_name()
            .expect("only a shared name is interned");
        let digest = identities.shared_name_digest(name);
        let recipe = identities.lookup_recipe(semantic);
        if let Some(&id) = self.by_digest.get(&digest) {
            let slot = usize::try_from(id - 1).expect("an identity id is positive");
            if recipe.is_some() && !self.has_recipe[slot] {
                self.has_recipe[slot] = true;
                self.late_recipes += 1;
            }
            return (id, None);
        }
        let id = i64::try_from(self.by_digest.len() + 1).expect("identity count fits an integer");
        self.by_digest.insert(digest, id);
        self.has_recipe.push(recipe.is_some());
        let row = match recipe {
            Some(recipe) => vec![
                Value::Integer(id),
                Value::Blob(digest.to_vec()),
                Value::Integer(language_code(recipe.semantic_language())),
                Value::Integer(code(ALL_RESOLUTION_NAMESPACES, recipe.namespace())),
                Value::Text(recipe.spelling().to_owned()),
            ],
            None => {
                self.without_recipe += 1;
                vec![
                    Value::Integer(id),
                    Value::Blob(digest.to_vec()),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ]
            }
        };
        (id, Some(row))
    }
}

/// Intern a shared name and write its row when it is new.
fn intern_into(
    db: &mut Db,
    interner: &mut Interner,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
) -> i64 {
    let (id, row) = interner.intern(identities, semantic);
    if let Some(row) = row {
        db.push(IDENTITIES, &row);
    }
    id
}

// ---------------------------------------------------------------------------
// Scratch database and its row sinks
// ---------------------------------------------------------------------------

struct TableSpec {
    name: &'static str,
    columns: &'static [&'static str],
    /// Column positions whose bound value is JSON text the statement wraps in
    /// `jsonb(...)`.
    jsonb: &'static [usize],
    /// Column positions that form the primary key, for the per-blob duplicate
    /// guard. Every primary key in the draft starts with `blob_id`.
    primary_key: &'static [usize],
}

struct Sink {
    spec: &'static TableSpec,
    statements: Vec<String>,
    pending: Vec<Value>,
    rows: u64,
    duplicates: u64,
    blob_rows: u64,
    per_blob: Vec<u32>,
    seen: HashSet<Box<[KeyPart]>>,
}

/// One primary-key column value, so that the per-blob duplicate guard works on
/// the text-labelled variant of a table as well as on the integer-coded one.
#[derive(PartialEq, Eq, Hash)]
enum KeyPart {
    Int(i64),
    Text(Box<str>),
}

fn key_part(table: &str, value: &Value) -> KeyPart {
    match value {
        Value::Integer(value) => KeyPart::Int(*value),
        Value::Text(value) => KeyPart::Text(value.as_str().into()),
        other => panic!("{table} primary key column is {other:?}"),
    }
}

impl Sink {
    fn new(spec: &'static TableSpec, batch: usize) -> Self {
        Self {
            spec,
            statements: (1..=batch).map(|rows| insert_sql(spec, rows)).collect(),
            pending: Vec::new(),
            rows: 0,
            duplicates: 0,
            blob_rows: 0,
            per_blob: Vec::new(),
            seen: HashSet::default(),
        }
    }

    fn batch(&self) -> usize {
        self.statements.len()
    }

    fn end_blob(&mut self) {
        self.per_blob
            .push(u32::try_from(self.blob_rows).expect("a blob's rows fit u32"));
        self.blob_rows = 0;
        self.seen.clear();
    }
}

fn insert_sql(spec: &TableSpec, rows: usize) -> String {
    let mut sql = format!(
        "INSERT INTO {}({}) VALUES ",
        spec.name,
        spec.columns.join(", ")
    );
    let mut parameter = 0;
    for row in 0..rows {
        if row > 0 {
            sql.push(',');
        }
        sql.push('(');
        for position in 0..spec.columns.len() {
            if position > 0 {
                sql.push(',');
            }
            parameter += 1;
            if spec.jsonb.contains(&position) {
                sql.push_str(&format!("jsonb(?{parameter})"));
            } else {
                sql.push_str(&format!("?{parameter}"));
            }
        }
        sql.push(')');
    }
    sql
}

struct Db {
    conn: Connection,
    sinks: Vec<Sink>,
    write_time: Duration,
}

impl Db {
    fn create(path: &Path, sections: &[&str], foreign_keys: bool, batch: usize) -> Self {
        for suffix in ["", "-wal", "-shm"] {
            let sibling = PathBuf::from(format!("{}{suffix}", path.display()));
            if sibling.exists() {
                std::fs::remove_file(&sibling).expect("remove a previous scratch database");
            }
        }
        let conn = Connection::open(path).expect("open the scratch database");
        conn.execute_batch(&format!(
            "PRAGMA page_size={PAGE_SIZE}; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
        ))
        .expect("scratch database pragmas");
        conn.execute_batch(&schema_text(sections, foreign_keys))
            .expect("the draft DDL loads");
        // Every variant keeps the `blob_id` cascade and the `identity_id` key,
        // which the owner's decision 4 keeps in any case, and the store turns
        // foreign keys on for its own connections.
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys");
        Self {
            conn,
            // The two parent tables write one row at a time whatever the
            // variant's batch is: an immediate foreign key needs the parent row
            // in the database before its children, and buffering the header row
            // of a blob behind fifteen other blobs would break that.
            sinks: TABLES
                .iter()
                .enumerate()
                .map(|(index, spec)| Sink::new(spec, if index <= BLOB_FACTS { 1 } else { batch }))
                .collect(),
            write_time: Duration::ZERO,
        }
    }

    fn push(&mut self, table: usize, row: &[Value]) {
        let sink = &mut self.sinks[table];
        assert_eq!(row.len(), sink.spec.columns.len(), "{}", sink.spec.name);
        if !sink.spec.primary_key.is_empty() {
            let key = sink
                .spec
                .primary_key
                .iter()
                .map(|position| key_part(sink.spec.name, &row[*position]))
                .collect::<Box<[KeyPart]>>();
            if !sink.seen.insert(key) {
                sink.duplicates += 1;
                return;
            }
        }
        sink.pending.extend_from_slice(row);
        sink.rows += 1;
        sink.blob_rows += 1;
        if sink.pending.len() == sink.batch() * sink.spec.columns.len() {
            let started = Instant::now();
            flush(&self.conn, sink);
            self.write_time += started.elapsed();
        }
    }

    fn flush_all(&mut self) {
        let started = Instant::now();
        for sink in &mut self.sinks {
            flush(&self.conn, sink);
        }
        self.write_time += started.elapsed();
    }

    fn transact(&mut self, statement: &str) {
        let started = Instant::now();
        self.conn.execute_batch(statement).expect("transaction");
        self.write_time += started.elapsed();
    }

    fn end_blob(&mut self) {
        for sink in &mut self.sinks {
            sink.end_blob();
        }
    }

    fn rows(&self) -> u64 {
        self.sinks.iter().map(|sink| sink.rows).sum()
    }
}

fn flush(conn: &Connection, sink: &mut Sink) {
    if sink.pending.is_empty() {
        return;
    }
    let rows = sink.pending.len() / sink.spec.columns.len();
    let sql = &sink.statements[rows - 1];
    let mut statement = conn
        .prepare_cached(sql)
        .unwrap_or_else(|error| panic!("prepare {}: {error}", sink.spec.name));
    statement
        .execute(params_from_iter(sink.pending.iter()))
        .unwrap_or_else(|error| panic!("insert into {}: {error}", sink.spec.name));
    sink.pending.clear();
}

/// The sections of the DDL a variant loads, with the foreign-key marker lines
/// kept or dropped.
fn schema_text(sections: &[&str], foreign_keys: bool) -> String {
    let mut current: Option<&str> = None;
    let mut parts = vec![String::new(); sections.len()];
    for line in DRAFT_SCHEMA.lines() {
        if let Some(name) = line.strip_prefix("-- @section ") {
            current = Some(name.trim());
            continue;
        }
        let Some(section) = current else {
            continue;
        };
        let Some(index) = sections.iter().position(|name| *name == section) else {
            continue;
        };
        match line.strip_prefix("--+fk ") {
            Some(rest) => {
                if foreign_keys {
                    parts[index].push_str(rest);
                    parts[index].push('\n');
                }
            }
            None if line.trim() == "--+fk" => {}
            None => {
                parts[index].push_str(line);
                parts[index].push('\n');
            }
        }
    }
    parts.join("\n")
}

// ---------------------------------------------------------------------------
// The tables, in the order the loader writes them
// ---------------------------------------------------------------------------

macro_rules! tables {
    ($($index:ident = $name:literal {
        columns: [$($column:literal),* $(,)?],
        jsonb: [$($jsonb:literal),*],
        key: [$($key:literal),*]
    },)+) => {
        static TABLES: &[TableSpec] = &[
            $(TableSpec {
                name: $name,
                columns: &[$($column),*],
                jsonb: &[$($jsonb),*],
                primary_key: &[$($key),*],
            }),+
        ];
        tables!(@indexes 0usize; $($index),+);
    };
    (@indexes $next:expr; $head:ident) => {
        const $head: usize = $next;
    };
    (@indexes $next:expr; $head:ident, $($rest:ident),+) => {
        const $head: usize = $next;
        tables!(@indexes $next + 1; $($rest),+);
    };
}

tables! {
    IDENTITIES = "resolution_identities" {
        columns: ["id", "identity_digest", "semantic_language", "namespace", "spelling"],
        jsonb: [],
        key: []
    },
    BLOB_FACTS = "resolution_blob_facts" {
        columns: ["blob_id", "semantic_language", "producer_epoch", "facts_digest", "demand_rows"],
        jsonb: [],
        key: []
    },
    SEMANTICS = "resolution_semantics" {
        columns: ["blob_id", "semantic_key"],
        jsonb: [],
        key: []
    },
    NODES = "resolution_nodes" {
        columns: ["blob_id", "node_key", "kind"],
        jsonb: [],
        key: []
    },
    STACK_VARIABLES = "resolution_stack_variables" {
        columns: ["blob_id", "variable_key"],
        jsonb: [],
        key: []
    },
    SITES = "resolution_sites" {
        columns: [
            "blob_id", "site", "role", "semantic", "node", "namespace", "site_kind",
            "start_byte", "end_byte", "unqualified", "owner", "receiver_origin",
        ],
        jsonb: [],
        key: [0, 1]
    },
    PATHS = "resolution_paths" {
        columns: [
            "blob_id", "path", "start_node", "start_lead_local", "start_lead_identity",
            "start_lead_scoped", "end_node", "end_lead_local", "end_lead_identity",
            "end_lead_scoped", "root_terminal", "body", "end_fixed_key", "end_open_tail",
        ],
        jsonb: [11],
        key: [0, 1]
    },
    GAPS = "resolution_gaps" {
        columns: [
            "blob_id", "covers", "subject", "lookup", "gap", "reason_kind", "reason",
            "boundary_status", "site", "origin",
        ],
        jsonb: [],
        key: [0, 1, 2, 3, 4]
    },
    TYPE_FRONTIERS = "resolution_type_frontiers" {
        columns: ["blob_id", "slot", "role", "identity_reference", "identity_node"],
        jsonb: [],
        key: [0, 1]
    },
    TYPE_TRANSFERS = "resolution_type_transfers" {
        columns: [
            "blob_id", "source_slot", "rule", "target_slot", "kind", "indirection_delta",
            "reference_indirection_delta", "value_transform", "completion",
        ],
        jsonb: [8],
        key: [0, 1, 2]
    },
    TYPE_COMPONENTS = "resolution_type_components" {
        columns: ["blob_id", "container_slot", "constructor", "kind", "component_slot"],
        jsonb: [],
        key: [0, 1, 3]
    },
    UNDERLYING_TYPES = "resolution_underlying_types" {
        columns: ["blob_id", "definition", "slot"],
        jsonb: [],
        key: [0, 1]
    },
    INTRINSIC_SEEDS = "resolution_intrinsic_seeds" {
        columns: ["blob_id", "slot", "kind", "spelling", "possible_values", "completion"],
        jsonb: [4, 5],
        key: [0, 1]
    },
    INTRINSIC_SEED_IDENTITIES = "resolution_intrinsic_seed_identities" {
        columns: ["blob_id", "identity_id", "slot"],
        jsonb: [],
        key: [0, 1, 2]
    },
    BINDING_PROJECTIONS = "resolution_binding_projections" {
        columns: ["blob_id", "reference", "output_slot", "kind"],
        jsonb: [],
        key: [0, 1, 2]
    },
    QUALIFIED_ROUTES = "resolution_qualified_routes" {
        columns: [
            "blob_id", "reference", "precedence_ordinal", "qualifier_slot", "lookup",
            "source_lookup", "namespace", "projection_output_slot", "projection_kind",
            "coarse_gap_reason",
        ],
        jsonb: [],
        key: [0, 1, 2]
    },
    DECLARATION_TYPES = "resolution_declaration_types" {
        columns: ["blob_id", "definition", "role", "slot"],
        jsonb: [],
        key: [0, 1, 2, 3]
    },
    MEMBER_SCOPES = "resolution_member_scopes" {
        columns: ["blob_id", "definition", "scope_head"],
        jsonb: [],
        key: [0, 1]
    },
    MEMBER_OWNERS = "resolution_member_owners" {
        columns: [
            "blob_id", "definition", "owner_definition", "owner_scope_head", "kind",
            "access", "qualifier_compatibility",
        ],
        jsonb: [],
        key: [0, 1, 2]
    },
    DEFERRED_MEMBER_OWNERS = "resolution_deferred_member_owners" {
        columns: ["blob_id", "definition", "seq", "lookup", "body"],
        jsonb: [4],
        key: [0, 1, 2]
    },
    CONSTRUCTION_REQUIREMENTS = "resolution_construction_requirements" {
        columns: ["blob_id", "definition", "required_owner_definition", "kind"],
        jsonb: [],
        key: [0, 1, 2, 3]
    },
    SUPERTYPES = "resolution_supertypes" {
        columns: ["blob_id", "definition", "reference", "frontier", "kind"],
        jsonb: [],
        key: [0, 1, 2]
    },
    DEFINITION_PROPERTY_GAPS = "resolution_definition_property_gaps" {
        columns: ["blob_id", "definition", "seq", "kind", "frontier", "reason", "site"],
        jsonb: [],
        key: [0, 1, 2]
    },
    CALL_OBLIGATIONS = "resolution_call_obligations" {
        columns: [
            "blob_id", "callee_reference", "call", "receiver_slot", "result_slot",
            "explicit_type_argument_count", "applicability_reason", "argument_slots",
            "type_argument_slots", "eligible_rules", "completion",
        ],
        jsonb: [7, 8, 9, 10],
        key: [0, 1]
    },
    CALLABLE_SIGNATURES = "resolution_callable_signatures" {
        columns: ["blob_id", "definition", "body"],
        jsonb: [2],
        key: [0, 1]
    },
}

// ---------------------------------------------------------------------------
// Keys inside a blob
// ---------------------------------------------------------------------------

/// The universal root is not a node of any blob.
fn node_key(keys: &ResolutionLocalKeys, node: BindingNodeId) -> i64 {
    if node == BindingNodeId::universal_root() {
        -1
    } else {
        keys.node(node)
    }
}

/// One symbol inside a path body: `>= 0` a local semantic key, `< 0` minus the
/// interned id of a shared name.
fn signed_semantic(
    db: &mut Db,
    interner: &mut Interner,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
) -> i64 {
    let identity = identities
        .semantic_identity(semantic)
        .expect("an emitted semantic is in its blob's catalog");
    match identity.space() {
        ResolutionSemanticIdentitySpace::FragmentLocal => keys.semantic(semantic),
        ResolutionSemanticIdentitySpace::Shared => -intern_into(db, interner, identities, semantic),
    }
}

const fn node_kind_code(kind: &BindingNodeKind) -> i64 {
    match kind {
        BindingNodeKind::Root => 0,
        BindingNodeKind::Scope => 1,
        BindingNodeKind::PushSymbol(_) => 2,
        BindingNodeKind::PopSymbol(_) => 3,
        BindingNodeKind::PushScopedSymbol(_) => 4,
        BindingNodeKind::PopScopedSymbol(_) => 5,
        BindingNodeKind::DropScopes => 6,
        BindingNodeKind::JumpToScope(_) => 7,
        BindingNodeKind::Reference(_) => 8,
        BindingNodeKind::Definition(_) => 9,
    }
}

/// `0` selected, otherwise one more than the rejection reason's code.
fn candidate_outcome_code(outcome: CandidateOutcome) -> i64 {
    match outcome {
        CandidateOutcome::Selected => 0,
        CandidateOutcome::Rejected(reason) => 1 + code(ALL_REJECTION_REASONS, reason),
    }
}

// ---------------------------------------------------------------------------
// What the loader counts that is not a row
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Census {
    blobs: u64,
    source_bytes: u64,
    parse: Duration,
    produce: Duration,
    lower: Duration,
    rows: Duration,
    // Measurement 6: the numbering option.
    sites: u64,
    reference_semantics: u64,
    definition_semantics: u64,
    both_role_semantics: u64,
    site_nodes: u64,
    nodes: u64,
    catalog_semantics: u64,
    catalog_paths: u64,
    catalog_stack_variables: u64,
    // Measurement 7: the path body.
    body_bytes: Vec<u32>,
    text_symbol_bytes: u64,
    text_scope_bytes: u64,
    text_precedence_bytes: u64,
    text_witness_bytes: u64,
    text_completion_bytes: u64,
    text_total_bytes: u64,
    // Seek keys.
    range_keys: Reservoir<[i64; 4]>,
    seed_keys: Reservoir<[i64; 3]>,
    forward_keys: Reservoir<[i64; 4]>,
    path_keys: Reservoir<[i64; 2]>,
}

/// A fixed-size deterministic sample of one key shape.
struct Reservoir<T> {
    capacity: usize,
    seen: u64,
    items: Vec<T>,
    rng: Rng,
}

impl<T: Copy> Reservoir<T> {
    fn new(capacity: usize, seed: u64) -> Self {
        Self {
            capacity,
            seen: 0,
            items: Vec::new(),
            rng: Rng(seed),
        }
    }

    fn offer(&mut self, item: T) {
        self.seen += 1;
        if self.items.len() < self.capacity {
            self.items.push(item);
            return;
        }
        if self.capacity == 0 {
            return;
        }
        let slot = usize::try_from(self.rng.next() % self.seen).expect("a slot fits usize");
        if slot < self.capacity {
            self.items[slot] = item;
        }
    }
}

impl<T: Copy> Default for Reservoir<T> {
    fn default() -> Self {
        Self::new(0, 1)
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
}

// ---------------------------------------------------------------------------
// Per-blob lowering and load
// ---------------------------------------------------------------------------

/// One blob's lowering, with the producer site table the draft's byte-range
/// index needs and a digest for the header row.
struct Lowering {
    lowered: LoweredResolutionFactsWithIdentityCatalog,
    sites: HashMap<u32, (ResolutionSiteKind, usize, usize)>,
    digest: [u8; 32],
    source_bytes: usize,
}

fn lower_blob(root: &Path, relative: &str, census: &mut Census) -> Lowering {
    let file = ProjectFile::new(root.to_path_buf(), Path::new(relative));
    let source = std::fs::read_to_string(root.join(relative)).expect("read a corpus source");
    let adapter = RustAdapter;

    let started = Instant::now();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("the Rust grammar");
    let tree = parser.parse(&source, None).expect("a complete parse tree");
    census.parse += started.elapsed();

    let started = Instant::now();
    let mut parsed = adapter.parse_file(&file, &source, &tree);
    parsed.add_file_scope(&file, &source);
    census.produce += started.elapsed();

    let started = Instant::now();
    let lowered = lower_resolution_facts_with_identity_catalog(
        BindingFragmentId::unmounted(),
        Language::Rust,
        &parsed.resolution_facts,
    );
    census.lower += started.elapsed();

    let sites = parsed
        .resolution_facts
        .sites
        .iter()
        .map(|site| (site.id.get(), (site.kind, site.start_byte, site.end_byte)))
        .collect::<HashMap<_, _>>();
    let mut hash = CanonicalHasher::new(b"bifrost-ld-facts-digest:v1");
    hash.field("source", source.as_bytes());
    Lowering {
        lowered,
        sites,
        digest: hash.finish(),
        source_bytes: source.len(),
    }
}

fn blob_facts_row(blob_id: i64, lowering: &Lowering) -> Vec<Value> {
    vec![
        Value::Integer(blob_id),
        Value::Integer(language_code(Language::Rust.config_label())),
        Value::Text(resolution_bundle_epoch(Language::Rust).to_owned()),
        Value::Blob(lowering.digest.to_vec()),
        Value::Integer(1),
    ]
}

#[allow(clippy::too_many_lines)]
fn write_blob(
    db: &mut Db,
    interner: &mut Interner,
    census: &mut Census,
    blob_id: i64,
    lowering: &Lowering,
    parents: bool,
) {
    let started = Instant::now();
    let write_before = db.write_time;
    let lowered = &lowering.lowered;
    let identities = lowered.identities();
    let keys = ResolutionLocalKeys::new(lowered, &CancellationToken::default())
        .expect("uncancelled key assignment");
    let lexical = lowered.lexical();
    let typed = lowered.typed();

    census.blobs += 1;
    census.source_bytes += lowering.source_bytes as u64;
    census.catalog_semantics += identities.semantics().len() as u64;
    census.catalog_paths += identities.paths().len() as u64;
    census.catalog_stack_variables += identities.stack_variables().len() as u64;
    census.nodes += identities.nodes().len() as u64;

    db.push(BLOB_FACTS, &blob_facts_row(blob_id, lowering));

    if parents {
        for index in 0..identities.semantics().len() {
            db.push(
                SEMANTICS,
                &[Value::Integer(blob_id), Value::Integer(index as i64)],
            );
        }
        // The draft keys a path endpoint on -1 for the universal root, so the
        // foreign-key variant needs a row for it. The rows era split the column
        // into a local key and a boundary key instead.
        db.push(
            NODES,
            &[
                Value::Integer(blob_id),
                Value::Integer(-1),
                Value::Integer(0),
            ],
        );
        for (node, kind) in lexical.nodes() {
            db.push(
                NODES,
                &[
                    Value::Integer(blob_id),
                    Value::Integer(keys.node(*node)),
                    Value::Integer(node_kind_code(kind)),
                ],
            );
        }
        for index in 0..identities.stack_variables().len() {
            db.push(
                STACK_VARIABLES,
                &[Value::Integer(blob_id), Value::Integer(index as i64)],
            );
        }
    }

    // --- sites -----------------------------------------------------------
    let mut references = HashSet::default();
    let mut definitions = HashSet::default();
    for site in lexical.semantics() {
        let metadata = site.site_metadata();
        let (kind, start_byte, end_byte) = *lowering
            .sites
            .get(&site.site().get())
            .expect("a lowered site names a producer site");
        if let Some(metadata) = metadata {
            assert_eq!(metadata.start_byte(), start_byte);
            assert_eq!(metadata.end_byte(), end_byte);
            assert_eq!(metadata.site_kind(), kind);
        }
        let role = match site.role() {
            LoweredSemanticRole::Reference => {
                references.insert(site.semantic());
                0
            }
            LoweredSemanticRole::Definition => {
                definitions.insert(site.semantic());
                1
            }
        };
        let semantic = keys.semantic(site.semantic());
        census.sites += 1;
        census
            .range_keys
            .offer([blob_id, start_byte as i64, end_byte as i64, role]);
        census.seed_keys.offer([blob_id, role, semantic]);
        db.push(
            SITES,
            &[
                Value::Integer(blob_id),
                Value::Integer(i64::from(site.site().get())),
                Value::Integer(role),
                Value::Integer(semantic),
                Value::Integer(keys.node(site.node())),
                Value::Integer(code(ALL_RESOLUTION_NAMESPACES, site.namespace())),
                Value::Integer(code(ALL_RESOLUTION_SITE_KINDS, kind)),
                Value::Integer(start_byte as i64),
                Value::Integer(end_byte as i64),
                Value::Integer(i64::from(
                    metadata.is_some_and(|metadata| metadata.unqualified()),
                )),
                match site.reference_owner() {
                    None => Value::Null,
                    Some(None) => Value::Integer(-1),
                    Some(Some(owner)) => Value::Integer(keys.semantic(owner)),
                },
                site.callable_receiver_origin()
                    .map_or(Value::Null, |origin| {
                        Value::Integer(code(ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, origin))
                    }),
            ],
        );
    }
    census.reference_semantics += references.len() as u64;
    census.definition_semantics += definitions.len() as u64;
    census.both_role_semantics += references
        .iter()
        .filter(|semantic| definitions.contains(*semantic))
        .count() as u64;
    census.site_nodes += lexical.semantics().len() as u64;

    // --- paths -----------------------------------------------------------
    for (path_id, path) in lexical.paths() {
        let path_key = keys.path(*path_id);
        let mut variables: Vec<(StackVariableId, i64)> = Vec::new();
        let body = path_body(
            db,
            interner,
            census,
            &keys,
            identities,
            path,
            &mut variables,
        );
        let start = endpoint_lead(db, interner, &keys, identities, path.start());
        let end = endpoint_lead(db, interner, &keys, identities, path.end());
        let root_terminal = root_terminal_identity(db, interner, identities, path);
        let root_key = (path.end().node() == BindingNodeId::universal_root()).then(|| {
            let mut key = super::resolution_rows::RootKeyBuilder::default();
            for symbol in path.end().symbols().fixed() {
                let signed = signed_semantic(db, interner, &keys, identities, symbol.symbol());
                if signed < 0 {
                    key.push(None, Some(-signed), symbol.scopes().is_some());
                } else {
                    key.push(Some(signed), None, symbol.scopes().is_some());
                }
            }
            key.finish().0
        });
        let root_tail = root_key
            .as_ref()
            .map(|_| i64::from(path.end().symbols().tail().is_some()));
        census
            .body_bytes
            .push(u32::try_from(body.len()).expect("a body length fits u32"));
        census.forward_keys.offer([
            blob_id,
            node_key(&keys, path.start().node()),
            start.1.unwrap_or(i64::MIN),
            start.0.unwrap_or(i64::MIN),
        ]);
        census.path_keys.offer([blob_id, path_key]);
        db.push(
            PATHS,
            &[
                Value::Integer(blob_id),
                Value::Integer(path_key),
                Value::Integer(node_key(&keys, path.start().node())),
                start.0.map_or(Value::Null, Value::Integer),
                start.1.map_or(Value::Null, Value::Integer),
                Value::Integer(i64::from(start.2)),
                Value::Integer(node_key(&keys, path.end().node())),
                end.0.map_or(Value::Null, Value::Integer),
                end.1.map_or(Value::Null, Value::Integer),
                Value::Integer(i64::from(end.2)),
                root_terminal.map_or(Value::Null, Value::Integer),
                Value::Text(body),
                root_key.map_or(Value::Null, Value::Text),
                root_tail.map_or(Value::Null, Value::Integer),
            ],
        );
    }

    // --- gaps ------------------------------------------------------------
    let mut ordinals: HashMap<(i64, i64, i64), i64> = HashMap::default();
    for gap in lexical.gaps() {
        let (covers, subject, lookup) = gap_address(db, interner, &keys, identities, gap);
        let ordinal = ordinals.entry((covers, subject, lookup)).or_insert(0);
        let gap_ordinal = *ordinal;
        *ordinal += 1;
        let (reason_kind, boundary_status) = gap.origin().completion_reason();
        db.push(
            GAPS,
            &[
                Value::Integer(blob_id),
                Value::Integer(covers),
                Value::Integer(subject),
                Value::Integer(lookup),
                Value::Integer(gap_ordinal),
                Value::Integer(code(ALL_RESOLUTION_COMPLETION_REASON_KINDS, reason_kind)),
                Value::Integer(keys.semantic(gap.reason_semantic())),
                boundary_status.map_or(Value::Null, |status| {
                    Value::Integer(code(ALL_BOUNDARY_STATUSES, status))
                }),
                Value::Integer(i64::from(gap.site().get())),
                Value::Integer(code(ALL_RESOLUTION_GAP_ORIGIN_KINDS, gap.origin().kind())),
            ],
        );
    }

    // --- typed facts -----------------------------------------------------
    for frontier in typed.frontiers() {
        let observation = frontier.type_identity_reference();
        db.push(
            TYPE_FRONTIERS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(frontier.slot())),
                Value::Integer(code(ALL_RESOLUTION_TYPE_SLOT_ROLES, frontier.role())),
                observation.map_or(Value::Null, |(reference, _)| {
                    Value::Integer(keys.semantic(reference))
                }),
                observation.map_or(Value::Null, |(_, node)| {
                    Value::Integer(node_key(&keys, node))
                }),
            ],
        );
    }
    for transfer in typed.transfers() {
        let rule = transfer.rule();
        db.push(
            TYPE_TRANSFERS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(transfer.source_slot())),
                Value::Integer(keys.semantic(rule.semantic())),
                Value::Integer(keys.semantic(rule.target_slot())),
                Value::Integer(code(ALL_RESOLUTION_TYPE_TRANSFER_KINDS, transfer.kind())),
                Value::Integer(rule.indirection_delta()),
                Value::Integer(rule.reference_indirection_delta()),
                Value::Integer(match rule.value_transform() {
                    TypeTransferValueTransform::Preserve => 0,
                    TypeTransferValueTransform::ToRuntime { addressable: false } => 1,
                    TypeTransferValueTransform::ToRuntime { addressable: true } => 2,
                    TypeTransferValueTransform::ToNoValue => 3,
                    TypeTransferValueTransform::TypeObjectOnly => 4,
                    TypeTransferValueTransform::AddressableRuntimeOnly => 5,
                    TypeTransferValueTransform::AddressableOperandOnly => 6,
                    TypeTransferValueTransform::RuntimeOnly => 7,
                }),
                completion_value(&keys, rule.completion()),
            ],
        );
    }
    for seed in typed.intrinsic_seeds() {
        let state = seed.frontier();
        let slot = keys.semantic(state.slot());
        let mut values = String::new();
        open(&mut values);
        let mut seen = HashSet::default();
        for value in state.possible_values() {
            let ty = value.ty();
            let signed = signed_semantic(db, interner, &keys, identities, ty.identity());
            open(&mut values);
            push_int(&mut values, i64::from(value.addressable().is_some()));
            push_int(&mut values, signed);
            push_int(&mut values, i64::from(ty.indirection()));
            push_int(&mut values, i64::from(ty.reference_indirection()));
            push_option(&mut values, value.addressable().map(i64::from));
            close(&mut values);
            if signed < 0 && seen.insert(-signed) {
                db.push(
                    INTRINSIC_SEED_IDENTITIES,
                    &[
                        Value::Integer(blob_id),
                        Value::Integer(-signed),
                        Value::Integer(slot),
                    ],
                );
            }
        }
        close(&mut values);
        db.push(
            INTRINSIC_SEEDS,
            &[
                Value::Integer(blob_id),
                Value::Integer(slot),
                Value::Integer(code(ALL_INTRINSIC_TYPE_KINDS, seed.kind())),
                Value::Text(seed.spelling().to_owned()),
                Value::Text(values),
                completion_value(&keys, state.completion()),
            ],
        );
    }
    for projection in typed.projections() {
        db.push(
            BINDING_PROJECTIONS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(projection.reference())),
                Value::Integer(keys.semantic(projection.output_slot())),
                Value::Integer(code(ALL_BINDING_PROJECTION_KINDS, projection.kind())),
            ],
        );
    }
    for route in typed.qualified_routes() {
        let lookup = intern_into(db, interner, identities, route.lookup());
        let source_lookup = intern_into(db, interner, identities, route.source_lookup());
        db.push(
            QUALIFIED_ROUTES,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(route.reference())),
                Value::Integer(i64::from(route.precedence_ordinal())),
                Value::Integer(keys.semantic(route.qualifier_slot())),
                Value::Integer(lookup),
                Value::Integer(source_lookup),
                Value::Integer(code(ALL_RESOLUTION_NAMESPACES, route.namespace())),
                Value::Integer(keys.semantic(route.projection_output_slot())),
                Value::Integer(code(ALL_BINDING_PROJECTION_KINDS, route.projection_kind())),
                Value::Integer(keys.semantic(route.coarse_gap_reason())),
            ],
        );
    }
    for property in typed.declaration_types() {
        db.push(
            DECLARATION_TYPES,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(property.definition())),
                Value::Integer(code(ALL_DECLARATION_TYPE_ROLES, property.role())),
                Value::Integer(keys.semantic(property.slot())),
            ],
        );
    }
    for property in typed.member_scopes() {
        db.push(
            MEMBER_SCOPES,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(property.definition())),
                Value::Integer(keys.node(property.scope_head())),
            ],
        );
    }
    for property in typed.member_owners() {
        db.push(
            MEMBER_OWNERS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(property.definition())),
                Value::Integer(keys.semantic(property.owner_definition())),
                Value::Integer(keys.node(property.owner_scope_head())),
                Value::Integer(code(ALL_RESOLUTION_MEMBER_KINDS, property.kind())),
                Value::Integer(code(ALL_RESOLUTION_MEMBER_ACCESSES, property.access())),
                Value::Integer(code(
                    ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
                    property.qualifier_compatibility(),
                )),
            ],
        );
    }
    let mut deferred_seq: HashMap<i64, i64> = HashMap::default();
    for property in typed.deferred_member_owners() {
        let definition = keys.semantic(property.definition());
        let seq = deferred_seq.entry(definition).or_insert(0);
        let ordinal = *seq;
        *seq += 1;
        let mut body = String::new();
        open(&mut body);
        push_int(&mut body, keys.semantic(property.owner_frontier()));
        push_option(
            &mut body,
            property
                .hierarchy_frontier()
                .map(|frontier| keys.semantic(frontier)),
        );
        push_int(
            &mut body,
            code(ALL_RESOLUTION_MEMBER_KINDS, property.kind()),
        );
        push_int(
            &mut body,
            code(ALL_RESOLUTION_MEMBER_ACCESSES, property.access()),
        );
        push_int(
            &mut body,
            code(
                ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
                property.qualifier_compatibility(),
            ),
        );
        close(&mut body);
        let lookup = intern_into(db, interner, identities, property.lookup());
        db.push(
            DEFERRED_MEMBER_OWNERS,
            &[
                Value::Integer(blob_id),
                Value::Integer(definition),
                Value::Integer(ordinal),
                Value::Integer(lookup),
                Value::Text(body),
            ],
        );
    }
    for property in typed.construction_requirements() {
        db.push(
            CONSTRUCTION_REQUIREMENTS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(property.definition())),
                Value::Integer(keys.semantic(property.required_owner_definition())),
                Value::Integer(code(
                    ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
                    property.kind(),
                )),
            ],
        );
    }
    for property in typed.supertypes() {
        db.push(
            SUPERTYPES,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(property.definition())),
                Value::Integer(keys.semantic(property.reference())),
                Value::Integer(keys.semantic(property.frontier())),
                Value::Integer(code(ALL_RESOLUTION_SUPERTYPE_KINDS, property.kind())),
            ],
        );
    }
    let mut gap_seq: HashMap<i64, i64> = HashMap::default();
    for gap in typed.property_gaps() {
        let definition = keys.semantic(gap.definition());
        let seq = gap_seq.entry(definition).or_insert(0);
        let ordinal = *seq;
        *seq += 1;
        db.push(
            DEFINITION_PROPERTY_GAPS,
            &[
                Value::Integer(blob_id),
                Value::Integer(definition),
                Value::Integer(ordinal),
                Value::Integer(code(ALL_RESOLUTION_GAP_KINDS, gap.kind())),
                Value::Integer(keys.semantic(gap.frontier())),
                Value::Integer(keys.semantic(gap.reason_semantic())),
                Value::Integer(i64::from(gap.source_site().get())),
            ],
        );
    }
    for obligation in typed.call_obligations() {
        let mut arguments = String::new();
        open(&mut arguments);
        for slot in obligation.argument_slots() {
            push_int(&mut arguments, keys.semantic(*slot));
        }
        close(&mut arguments);
        let mut rules = String::new();
        open(&mut rules);
        for rule in obligation.eligible_rules() {
            push_int(&mut rules, code(ALL_RESOLUTION_ENGINE_RULE_KINDS, *rule));
        }
        close(&mut rules);
        let mut type_arguments = String::new();
        open(&mut type_arguments);
        for slots in [
            obligation.type_argument_slots(),
            obligation.owner_type_argument_slots(),
        ] {
            open(&mut type_arguments);
            for slot in slots {
                push_int(&mut type_arguments, keys.semantic(*slot));
            }
            close(&mut type_arguments);
        }
        for slot in [
            obligation.expected_result_slot(),
            obligation.owner_type_segment(),
        ] {
            push_option(&mut type_arguments, slot.map(|slot| keys.semantic(slot)));
        }
        open(&mut type_arguments);
        for slot in obligation.extra_result_slots() {
            push_int(&mut type_arguments, keys.semantic(*slot));
        }
        close(&mut type_arguments);
        close(&mut type_arguments);
        db.push(
            CALL_OBLIGATIONS,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(obligation.callee_reference())),
                Value::Integer(keys.semantic(obligation.call())),
                obligation
                    .receiver_slot()
                    .map_or(Value::Null, |slot| Value::Integer(keys.semantic(slot))),
                Value::Integer(keys.semantic(obligation.result_slot())),
                Value::Integer(i64::from(obligation.explicit_type_argument_count())),
                Value::Integer(keys.semantic(obligation.applicability_reason())),
                Value::Text(arguments),
                Value::Text(type_arguments),
                Value::Text(rules),
                completion_value(&keys, obligation.completion()),
            ],
        );
    }
    for signature in typed.callable_signatures() {
        let mut body = String::new();
        open(&mut body);
        push_int(&mut body, i64::from(signature.type_parameter_count()));
        open(&mut body);
        for parameter in signature.parameters() {
            open(&mut body);
            push_int(&mut body, keys.semantic(parameter.definition()));
            push_int(&mut body, keys.semantic(parameter.slot()));
            push_int(&mut body, i64::from(parameter.repeated()));
            close(&mut body);
        }
        close(&mut body);
        write_completion(&mut body, &keys, signature.completion());
        open(&mut body);
        for binding in signature.result_bindings() {
            open(&mut body);
            push_int(&mut body, i64::from(binding.ordinal()));
            push_int(&mut body, binding.indirection_delta());
            push_int(&mut body, binding.reference_indirection_delta());
            close(&mut body);
        }
        close(&mut body);
        push_option(
            &mut body,
            signature
                .receiver()
                .map(|form| code(ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS, form)),
        );
        for parameter in [
            signature.result_type_parameter(),
            signature.result_owner_type_parameter(),
        ] {
            match parameter {
                Some(parameter) => {
                    open(&mut body);
                    push_int(&mut body, i64::from(parameter.ordinal()));
                    push_int(&mut body, parameter.indirection_delta());
                    push_int(&mut body, parameter.reference_indirection_delta());
                    close(&mut body);
                }
                None => push_option(&mut body, None),
            }
        }
        open(&mut body);
        for result in signature.result_types() {
            open(&mut body);
            push_int(&mut body, i64::from(result.ordinal()));
            push_int(&mut body, keys.semantic(result.slot()));
            close(&mut body);
        }
        close(&mut body);
        close(&mut body);
        db.push(
            CALLABLE_SIGNATURES,
            &[
                Value::Integer(blob_id),
                Value::Integer(keys.semantic(signature.definition())),
                Value::Text(body),
            ],
        );
    }
    census.rows += started.elapsed() - (db.write_time - write_before);
}

/// `(lead_local, lead_identity, lead_scoped)` for one endpoint.
fn endpoint_lead(
    db: &mut Db,
    interner: &mut Interner,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    endpoint: &crate::analyzer::resolution::EndpointSignature,
) -> (Option<i64>, Option<i64>, bool) {
    let Some(symbol) = endpoint.symbols().fixed().first() else {
        return (None, None, false);
    };
    let scoped = symbol.scopes().is_some();
    let identity = identities
        .semantic_identity(symbol.symbol())
        .expect("a lead symbol is in the catalog");
    match identity.space() {
        ResolutionSemanticIdentitySpace::FragmentLocal => {
            (Some(keys.semantic(symbol.symbol())), None, scoped)
        }
        ResolutionSemanticIdentitySpace::Shared => (
            None,
            Some(intern_into(db, interner, identities, symbol.symbol())),
            scoped,
        ),
    }
}

fn root_terminal_identity(
    db: &mut Db,
    interner: &mut Interner,
    identities: &ResolutionIdentityCatalog,
    path: &PartialPath,
) -> Option<i64> {
    if path.end().node() != BindingNodeId::universal_root() {
        return None;
    }
    let fixed = path.end().symbols().fixed();
    if fixed.len() < 3 {
        return None;
    }
    let terminal = fixed
        .last()
        .expect("a three-symbol stack has a last symbol");
    let identity = identities
        .semantic_identity(terminal.symbol())
        .expect("a terminal symbol is in the catalog");
    (identity.space() == ResolutionSemanticIdentitySpace::Shared)
        .then(|| intern_into(db, interner, identities, terminal.symbol()))
}

/// The per-path number of one stack variable, in order of first appearance in
/// the body's serialization order.
fn variable_number(variables: &mut Vec<(StackVariableId, i64)>, variable: StackVariableId) -> i64 {
    if let Some((_, number)) = variables.iter().find(|(known, _)| *known == variable) {
        return *number;
    }
    let number = i64::try_from(variables.len()).expect("a path's variables fit an integer");
    variables.push((variable, number));
    number
}

/// `[start_symbols, start_symbol_tail, start_scopes, start_scope_tail,
/// end_symbols, end_symbol_tail, end_scopes, end_scope_tail, precedence,
/// witness, completion]`.
fn path_body(
    db: &mut Db,
    interner: &mut Interner,
    census: &mut Census,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    path: &PartialPath,
    variables: &mut Vec<(StackVariableId, i64)>,
) -> String {
    let mut out = String::new();
    let mut scope_bytes = 0usize;
    let mut symbol_bytes = 0usize;
    open(&mut out);
    for endpoint in [path.start(), path.end()] {
        let before = out.len();
        let before_scopes = scope_bytes;
        open(&mut out);
        for symbol in endpoint.symbols().fixed() {
            let signed = signed_semantic(db, interner, keys, identities, symbol.symbol());
            match symbol.scopes() {
                None => push_int(&mut out, signed),
                Some(scopes) => {
                    open(&mut out);
                    push_int(&mut out, signed);
                    let scope_start = out.len();
                    open(&mut out);
                    for scope in scopes.fixed() {
                        push_int(&mut out, node_key(keys, *scope));
                    }
                    close(&mut out);
                    push_option(
                        &mut out,
                        scopes
                            .tail()
                            .map(|variable| variable_number(variables, variable)),
                    );
                    scope_bytes += out.len() - scope_start;
                    close(&mut out);
                }
            }
        }
        close(&mut out);
        symbol_bytes += (out.len() - before) - (scope_bytes - before_scopes);
        push_option(
            &mut out,
            endpoint
                .symbols()
                .tail()
                .map(|variable| variable_number(variables, variable)),
        );
        let scope_start = out.len();
        open(&mut out);
        for scope in endpoint.scopes().fixed() {
            push_int(&mut out, node_key(keys, *scope));
        }
        close(&mut out);
        push_option(
            &mut out,
            endpoint
                .scopes()
                .tail()
                .map(|variable| variable_number(variables, variable)),
        );
        scope_bytes += out.len() - scope_start;
    }
    let precedence_start = out.len();
    open(&mut out);
    for step in path.precedence() {
        let signed = signed_semantic(db, interner, keys, identities, step.semantic);
        open(&mut out);
        push_int(&mut out, code(ALL_PRECEDENCE_TIERS, step.tier));
        push_int(&mut out, i64::from(step.ordinal));
        push_int(&mut out, signed);
        close(&mut out);
    }
    close(&mut out);
    let precedence_bytes = out.len() - precedence_start;
    let witness_start = out.len();
    open(&mut out);
    for step in path.witness() {
        match step {
            WitnessStep::Node(node) => push_int(&mut out, node_key(keys, *node)),
            WitnessStep::Candidate { semantic, outcome } => {
                let signed = signed_semantic(db, interner, keys, identities, *semantic);
                open(&mut out);
                push_int(&mut out, 1);
                push_int(&mut out, signed);
                push_int(&mut out, candidate_outcome_code(*outcome));
                close(&mut out);
            }
            WitnessStep::Boundary { semantic, status } => {
                let signed = signed_semantic(db, interner, keys, identities, *semantic);
                open(&mut out);
                push_int(&mut out, 2);
                push_int(&mut out, signed);
                push_int(&mut out, code(ALL_BOUNDARY_STATUSES, *status));
                close(&mut out);
            }
        }
    }
    close(&mut out);
    let witness_bytes = out.len() - witness_start;
    let completion_start = out.len();
    write_completion(&mut out, keys, path.completion());
    let completion_bytes = out.len() - completion_start;
    close(&mut out);

    census.text_symbol_bytes += symbol_bytes as u64;
    census.text_scope_bytes += scope_bytes as u64;
    census.text_precedence_bytes += precedence_bytes as u64;
    census.text_witness_bytes += witness_bytes as u64;
    census.text_completion_bytes += completion_bytes as u64;
    census.text_total_bytes += out.len() as u64;
    out
}

fn write_completion(
    out: &mut String,
    keys: &ResolutionLocalKeys,
    completion: &ResolutionCompletion,
) {
    open(out);
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        for reason in reasons.iter() {
            open(out);
            push_int(
                out,
                code(ALL_RESOLUTION_COMPLETION_REASON_KINDS, reason.kind()),
            );
            match reason {
                ResolutionIncompleteReason::CyclicExpansion(path) => {
                    push_int(out, keys.path(*path));
                }
                ResolutionIncompleteReason::InconsistentPrecedence(semantic)
                | ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    push_int(out, keys.semantic(*semantic));
                }
                ResolutionIncompleteReason::OpenBoundary { semantic, status } => {
                    push_int(out, keys.semantic(*semantic));
                    push_int(out, code(ALL_BOUNDARY_STATUSES, *status));
                }
                other => panic!("a lowered completion cannot carry {other:?}"),
            }
            close(out);
        }
    }
    close(out);
}

fn completion_value(keys: &ResolutionLocalKeys, completion: &ResolutionCompletion) -> Value {
    match completion {
        ResolutionCompletion::Complete => Value::Null,
        ResolutionCompletion::Incomplete(_) => {
            let mut out = String::new();
            write_completion(&mut out, keys, completion);
            Value::Text(out)
        }
    }
}

/// `(covers, subject, lookup)` for one gap row.
fn gap_address(
    db: &mut Db,
    interner: &mut Interner,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    gap: &LoweredCoverageGap,
) -> (i64, i64, i64) {
    match gap.frontier() {
        LoweringCoverageFrontier::Fragment => (0, 0, 0),
        LoweringCoverageFrontier::Enumeration => (1, 0, 0),
        LoweringCoverageFrontier::CandidateInventory { direction } => (
            match direction {
                LoweredCandidateDirection::Forward => 2,
                LoweredCandidateDirection::Reverse => 3,
            },
            0,
            0,
        ),
        LoweringCoverageFrontier::Reference { semantic, .. } => (4, keys.semantic(semantic), 0),
        LoweringCoverageFrontier::Candidate {
            direction,
            endpoint,
            lookup,
        } => {
            let covers = match direction {
                LoweredCandidateDirection::Forward => 5,
                LoweredCandidateDirection::Reverse => 6,
            };
            // 0 is "every lookup"; a local key is shifted up by one and a
            // shared name is minus its interned id, so neither can be 0.
            let lookup = lookup.map_or(0, |semantic| {
                let identity = identities
                    .semantic_identity(semantic)
                    .expect("a candidate lookup is in the catalog");
                match identity.space() {
                    ResolutionSemanticIdentitySpace::FragmentLocal => keys.semantic(semantic) + 1,
                    ResolutionSemanticIdentitySpace::Shared => {
                        -intern_into(db, interner, identities, semantic)
                    }
                }
            });
            (covers, node_key(keys, endpoint), lookup)
        }
        LoweringCoverageFrontier::Type { frontier } => (7, keys.semantic(frontier), 0),
    }
}

// ---------------------------------------------------------------------------
// Passes
// ---------------------------------------------------------------------------

struct Pass {
    name: &'static str,
    sections: &'static [&'static str],
    foreign_keys: bool,
    batch: usize,
    transaction_blobs: usize,
}

const PASSES: &[Pass] = &[
    Pass {
        name: "draft",
        sections: &["core", "draft"],
        foreign_keys: false,
        batch: 1,
        transaction_blobs: 1,
    },
    Pass {
        name: "txn64",
        sections: &["core", "draft"],
        foreign_keys: false,
        batch: 1,
        transaction_blobs: 64,
    },
    Pass {
        name: "batch16",
        sections: &["core", "draft"],
        foreign_keys: false,
        batch: 16,
        transaction_blobs: 1,
    },
    Pass {
        name: "txn64batch16",
        sections: &["core", "draft"],
        foreign_keys: false,
        batch: 16,
        transaction_blobs: 64,
    },
    Pass {
        name: "fk",
        sections: &["core", "fk_parents", "draft"],
        foreign_keys: true,
        batch: 1,
        transaction_blobs: 1,
    },
];

fn corpus_files(root: &Path) -> Vec<String> {
    let mut files = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != ".git")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        })
        .map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .expect("a corpus path is under the corpus root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    files.sort_unstable();
    files
}

fn percentile(values: &mut [u32], fraction: f64) -> u32 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let index = ((values.len() - 1) as f64 * fraction).round() as usize;
    values[index]
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|value| {
            value
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|_| "unknown".to_owned())
}

#[test]
#[ignore = "measurement: draft schema loader"]
fn draft_schema_loader() {
    let root = PathBuf::from(
        std::env::var_os("BIFROST_LD_CORPUS").expect("set BIFROST_LD_CORPUS to a corpus root"),
    );
    let out_dir = PathBuf::from(
        std::env::var_os("BIFROST_LD_DIR").expect("set BIFROST_LD_DIR to a scratch directory"),
    );
    std::fs::create_dir_all(&out_dir).expect("create the scratch directory");
    let requested = std::env::var("BIFROST_LD_PASSES").unwrap_or_else(|_| {
        let mut names = PASSES.iter().map(|pass| pass.name).collect::<Vec<_>>();
        names.push("enums");
        names.join(",")
    });
    let seeks = std::env::var("BIFROST_LD_SEEKS")
        .map(|value| value.parse::<usize>().expect("seek count"))
        .unwrap_or(100_000);
    let wanted = |name: &str| requested.split(',').any(|entry| entry.trim() == name);

    let files = corpus_files(&root);
    let total_bytes = files
        .iter()
        .map(|relative| {
            std::fs::metadata(root.join(relative))
                .expect("a corpus file")
                .len()
        })
        .sum::<u64>();
    eprintln!(
        "[ld] corpus={} files={} source_bytes={total_bytes} load={}",
        root.display(),
        files.len(),
        loadavg()
    );

    for pass in PASSES {
        if wanted(pass.name) {
            run_pass(pass, &root, &files, &out_dir, total_bytes, seeks);
        }
    }
    if wanted("enums") {
        run_enum_pass(&root, &files, &out_dir);
    }
}

#[allow(clippy::too_many_lines)]
fn run_pass(
    pass: &Pass,
    root: &Path,
    files: &[String],
    out_dir: &Path,
    total_bytes: u64,
    seeks: usize,
) {
    let path = out_dir.join(format!("ld-{}.db", pass.name));
    let mut db = Db::create(&path, pass.sections, pass.foreign_keys, pass.batch);
    let mut interner = Interner::new();
    let mut census = Census {
        range_keys: Reservoir::new(seeks, 11),
        seed_keys: Reservoir::new(seeks, 22),
        forward_keys: Reservoir::new(seeks, 33),
        path_keys: Reservoir::new(seeks, 44),
        ..Census::default()
    };
    let started = Instant::now();
    let mut open_transaction = false;
    for (index, relative) in files.iter().enumerate() {
        let blob_id = i64::try_from(index + 1).expect("a blob id fits an integer");
        let lowering = lower_blob(root, relative, &mut census);
        if !open_transaction {
            db.transact("BEGIN");
            open_transaction = true;
        }
        write_blob(
            &mut db,
            &mut interner,
            &mut census,
            blob_id,
            &lowering,
            pass.foreign_keys,
        );
        db.end_blob();
        if (index + 1) % pass.transaction_blobs == 0 {
            db.flush_all();
            db.transact("COMMIT");
            open_transaction = false;
        }
    }
    if open_transaction {
        db.flush_all();
        db.transact("COMMIT");
    }
    let wall = started.elapsed();
    db.conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint");

    let rows = db.rows();
    eprintln!(
        "[ld] pass={} wall_s={:.1} parse_s={:.1} produce_s={:.1} lower_s={:.1} rowbuild_s={:.1} \
         write_s={:.1} blobs={} rows={rows} rows_per_s={:.0} blobs_per_s={:.2} \
         write_rows_per_s={:.0} identities={} interner_bytes={} late_recipes={} \
         identities_without_recipe={} source_bytes={total_bytes} load={}",
        pass.name,
        wall.as_secs_f64(),
        census.parse.as_secs_f64(),
        census.produce.as_secs_f64(),
        census.lower.as_secs_f64(),
        census.rows.as_secs_f64(),
        db.write_time.as_secs_f64(),
        census.blobs,
        rows as f64 / wall.as_secs_f64(),
        census.blobs as f64 / wall.as_secs_f64(),
        rows as f64 / db.write_time.as_secs_f64(),
        interner.len(),
        interner.len() * 48,
        interner.late_recipes,
        interner.without_recipe,
        loadavg()
    );
    for sink in &db.sinks {
        if sink.rows == 0 {
            continue;
        }
        let mut per_blob = sink.per_blob.clone();
        let max = per_blob.iter().copied().max().unwrap_or(0);
        let p50 = percentile(&mut per_blob, 0.5);
        let p90 = percentile(&mut per_blob, 0.9);
        eprintln!(
            "[ld] pass={} table={} rows={} duplicates={} per_blob_p50={p50} per_blob_p90={p90} \
             per_blob_max={max}",
            pass.name, sink.spec.name, sink.rows, sink.duplicates,
        );
    }
    eprintln!(
        "[ld] pass={} sites={} reference_semantics={} definition_semantics={} \
         both_role_semantics={} site_nodes={} catalog_semantics={} catalog_nodes={} \
         catalog_paths={} catalog_stack_variables={}",
        pass.name,
        census.sites,
        census.reference_semantics,
        census.definition_semantics,
        census.both_role_semantics,
        census.site_nodes,
        census.catalog_semantics,
        census.nodes,
        census.catalog_paths,
        census.catalog_stack_variables,
    );
    let mut bodies = census.body_bytes.clone();
    let body_max = bodies.iter().copied().max().unwrap_or(0);
    eprintln!(
        "[ld] pass={} body_text_p50={} body_text_p90={} body_text_max={body_max} \
         body_text_total={} symbols={} scopes={} precedence={} witness={} completion={}",
        pass.name,
        percentile(&mut bodies, 0.5),
        percentile(&mut bodies, 0.9),
        census.text_total_bytes,
        census.text_symbol_bytes,
        census.text_scope_bytes,
        census.text_precedence_bytes,
        census.text_witness_bytes,
        census.text_completion_bytes,
    );
    let jsonb: (i64, i64, i64) = db
        .conn
        .query_row(
            "SELECT sum(length(body)), max(length(body)), count(*) FROM resolution_paths",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("path body bytes");
    eprintln!(
        "[ld] pass={} body_jsonb_total={} body_jsonb_max={} paths={}",
        pass.name, jsonb.0, jsonb.1, jsonb.2
    );

    if pass.name == "draft" {
        measure_seeks(&db.conn, &census, seeks);
    }
}

fn bind_value(value: i64) -> Value {
    if value == i64::MIN {
        Value::Null
    } else {
        Value::Integer(value)
    }
}

const SITE_BY_RANGE: &str = "SELECT site, semantic, node FROM resolution_sites \
     WHERE blob_id = ?1 AND start_byte = ?2 AND end_byte = ?3 AND role = ?4";
const SEED_BY_SEMANTIC: &str = "SELECT site, node, start_byte, end_byte FROM resolution_sites \
     WHERE blob_id = ?1 AND role = ?2 AND semantic = ?3";
const FORWARD_CANDIDATE: &str = "SELECT path FROM resolution_paths \
     WHERE blob_id = ?1 AND start_node = ?2 AND start_lead_identity IS ?3 \
       AND start_lead_local IS ?4";
const PATH_BODY: &str = "SELECT body FROM resolution_paths WHERE blob_id = ?1 AND path = ?2";
const PATH_BODY_JSON: &str =
    "SELECT json(body) FROM resolution_paths WHERE blob_id = ?1 AND path = ?2";

/// The plan of each measured statement, at a real sampled key: this build of
/// SQLite reads `sqlite_stat4`, so the bound values are part of what is pinned.
fn print_plans(conn: &Connection, census: &Census, state: &str) {
    let range = census.range_keys.items.first().copied().unwrap_or_default();
    let seed = census.seed_keys.items.first().copied().unwrap_or_default();
    let forward = census
        .forward_keys
        .items
        .first()
        .copied()
        .unwrap_or_default();
    let path = census.path_keys.items.first().copied().unwrap_or_default();
    for (label, sql, bindings) in [
        ("site_by_range", SITE_BY_RANGE, &range[..]),
        ("seed_by_semantic", SEED_BY_SEMANTIC, &seed[..]),
        ("forward_candidate", FORWARD_CANDIDATE, &forward[..]),
        ("path_body", PATH_BODY, &path[..]),
        ("path_body_json", PATH_BODY_JSON, &path[..]),
    ] {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("explain");
        let mut rows = statement
            .query(params_from_iter(bindings.iter().copied().map(bind_value)))
            .expect("query plan");
        let mut plan = Vec::new();
        while let Some(row) = rows.next().expect("plan row") {
            plan.push(row.get::<_, String>(3).expect("plan detail"));
        }
        eprintln!("[ld] plan {state} {label}: {}", plan.join(" | "));
    }
}

fn measure_seeks(conn: &Connection, census: &Census, seeks: usize) {
    print_plans(conn, census, "no-statistics");
    // The store refreshes planner statistics on build and on collection, so a
    // warm reader plans against them. `analysis_limit` matches `cache_gc`.
    conn.execute_batch("PRAGMA analysis_limit=1000; ANALYZE;")
        .expect("analyze");
    print_plans(conn, census, "analyzed");

    let mut timings = Vec::with_capacity(seeks);
    let empty = Instant::now();
    for _ in 0..seeks {
        let probe = Instant::now();
        timings.push(u32::try_from(probe.elapsed().as_nanos()).unwrap_or(u32::MAX));
    }
    eprintln!(
        "[ld] timer_overhead_ns_mean={:.1} p50={}",
        empty.elapsed().as_nanos() as f64 / seeks as f64,
        percentile(&mut timings, 0.5)
    );

    seek_shape(
        conn,
        "site_by_range",
        SITE_BY_RANGE,
        &census.range_keys.items,
    );
    seek_shape(
        conn,
        "seed_by_semantic",
        SEED_BY_SEMANTIC,
        &census.seed_keys.items,
    );
    seek_shape(
        conn,
        "forward_candidate",
        FORWARD_CANDIDATE,
        &census.forward_keys.items,
    );
    seek_shape(conn, "path_body", PATH_BODY, &census.path_keys.items);
    seek_decoded(conn, &census.path_keys.items);

    hash_probe("site_by_range", &census.range_keys.items);
    hash_probe("seed_by_semantic", &census.seed_keys.items);
    hash_probe("forward_candidate", &census.forward_keys.items);
    hash_probe("path_body", &census.path_keys.items);
}

fn seek_shape<const N: usize>(conn: &Connection, label: &str, sql: &str, keys: &[[i64; N]]) {
    if keys.is_empty() {
        return;
    }
    let mut rows_seen = 0u64;
    for key in keys.iter().take(keys.len().min(10_000)) {
        let mut statement = conn.prepare_cached(sql).expect("prepare");
        let mut query = statement
            .query(params_from_iter(key.iter().copied().map(bind_value)))
            .expect("query");
        while query.next().expect("row").is_some() {
            rows_seen += 1;
        }
    }
    let mut timings = Vec::with_capacity(keys.len());
    let started = Instant::now();
    for key in keys {
        let probe = Instant::now();
        let mut statement = conn.prepare_cached(sql).expect("prepare");
        let mut query = statement
            .query(params_from_iter(key.iter().copied().map(bind_value)))
            .expect("query");
        while query.next().expect("row").is_some() {
            rows_seen += 1;
        }
        timings.push(u32::try_from(probe.elapsed().as_nanos()).unwrap_or(u32::MAX));
    }
    let total = started.elapsed();
    let p50 = percentile(&mut timings.clone(), 0.5);
    let p90 = percentile(&mut timings, 0.9);
    eprintln!(
        "[ld] seek={label} probes={} mean_ns={:.0} p50_ns={p50} p90_ns={p90} rows_seen={rows_seen}",
        keys.len(),
        total.as_nanos() as f64 / keys.len() as f64,
    );
}

fn seek_decoded(conn: &Connection, keys: &[[i64; 2]]) {
    if keys.is_empty() {
        return;
    }
    let mut elements = 0u64;
    for key in keys.iter().take(keys.len().min(10_000)) {
        let mut statement = conn.prepare_cached(PATH_BODY_JSON).expect("prepare");
        let text: String = statement
            .query_row([key[0], key[1]], |row| row.get(0))
            .expect("body");
        elements += text.len() as u64;
    }
    let mut timings = Vec::with_capacity(keys.len());
    let started = Instant::now();
    for key in keys {
        let probe = Instant::now();
        let mut statement = conn.prepare_cached(PATH_BODY_JSON).expect("prepare");
        let text: String = statement
            .query_row([key[0], key[1]], |row| row.get(0))
            .expect("body");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("a decodable body");
        elements += parsed.as_array().expect("a positional body").len() as u64;
        timings.push(u32::try_from(probe.elapsed().as_nanos()).unwrap_or(u32::MAX));
    }
    let total = started.elapsed();
    let p50 = percentile(&mut timings.clone(), 0.5);
    let p90 = percentile(&mut timings, 0.9);
    eprintln!(
        "[ld] seek=path_body_decoded probes={} mean_ns={:.0} p50_ns={p50} p90_ns={p90} \
         checksum={elements}",
        keys.len(),
        total.as_nanos() as f64 / keys.len() as f64,
    );
}

fn hash_probe<const N: usize>(label: &str, keys: &[[i64; N]]) {
    if keys.is_empty() {
        return;
    }
    let map = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, index as i64))
        .collect::<HashMap<[i64; N], i64>>();
    let mut checksum = 0i64;
    for key in keys.iter().take(keys.len().min(10_000)) {
        checksum += map.get(key).copied().unwrap_or(0);
    }
    let started = Instant::now();
    for key in keys {
        checksum += map.get(key).copied().unwrap_or(0);
    }
    let total = started.elapsed();
    eprintln!(
        "[ld] hash={label} probes={} mean_ns={:.1} entries={} checksum={checksum}",
        keys.len(),
        total.as_nanos() as f64 / keys.len() as f64,
        map.len(),
    );
}

/// Decision 3: the same sites and gaps, once with integer codes and once with
/// the text labels the vocabulary macros publish.
#[allow(clippy::too_many_lines)]
fn run_enum_pass(root: &Path, files: &[String], out_dir: &Path) {
    let mut coded = Db::create(
        &out_dir.join("ld-enum-code.db"),
        &["core", "enum_code"],
        false,
        1,
    );
    let mut labelled = Db::create(
        &out_dir.join("ld-enum-text.db"),
        &["core", "enum_text"],
        false,
        1,
    );
    let mut census = Census::default();
    let mut interner = Interner::new();
    let started = Instant::now();
    for (index, relative) in files.iter().enumerate() {
        let blob_id = i64::try_from(index + 1).expect("a blob id fits an integer");
        let lowering = lower_blob(root, relative, &mut census);
        let lowered = &lowering.lowered;
        let identities = lowered.identities();
        let keys = ResolutionLocalKeys::new(lowered, &CancellationToken::default())
            .expect("uncancelled key assignment");
        coded.transact("BEGIN");
        labelled.transact("BEGIN");
        let header = blob_facts_row(blob_id, &lowering);
        coded.push(BLOB_FACTS, &header);
        labelled.push(BLOB_FACTS, &header);
        for site in lowered.lexical().semantics() {
            let metadata = site.site_metadata();
            let (kind, start_byte, end_byte) = *lowering
                .sites
                .get(&site.site().get())
                .expect("a lowered site names a producer site");
            let owner = match site.reference_owner() {
                None => Value::Null,
                Some(None) => Value::Integer(-1),
                Some(Some(owner)) => Value::Integer(keys.semantic(owner)),
            };
            let head = [
                Value::Integer(blob_id),
                Value::Integer(i64::from(site.site().get())),
            ];
            let middle = [
                Value::Integer(keys.semantic(site.semantic())),
                Value::Integer(keys.node(site.node())),
            ];
            let tail = [
                Value::Integer(start_byte as i64),
                Value::Integer(end_byte as i64),
                Value::Integer(i64::from(
                    metadata.is_some_and(|metadata| metadata.unqualified()),
                )),
                owner,
            ];
            coded.push(
                SITES,
                &[
                    head[0].clone(),
                    head[1].clone(),
                    Value::Integer(i64::from(site.role() == LoweredSemanticRole::Definition)),
                    middle[0].clone(),
                    middle[1].clone(),
                    Value::Integer(code(ALL_RESOLUTION_NAMESPACES, site.namespace())),
                    Value::Integer(code(ALL_RESOLUTION_SITE_KINDS, kind)),
                    tail[0].clone(),
                    tail[1].clone(),
                    tail[2].clone(),
                    tail[3].clone(),
                    site.callable_receiver_origin()
                        .map_or(Value::Null, |origin| {
                            Value::Integer(code(ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, origin))
                        }),
                ],
            );
            labelled.push(
                SITES,
                &[
                    head[0].clone(),
                    head[1].clone(),
                    Value::Text(
                        match site.role() {
                            LoweredSemanticRole::Reference => "reference",
                            LoweredSemanticRole::Definition => "definition",
                        }
                        .to_owned(),
                    ),
                    middle[0].clone(),
                    middle[1].clone(),
                    Value::Text(site.namespace().label().to_owned()),
                    Value::Text(kind.label().to_owned()),
                    tail[0].clone(),
                    tail[1].clone(),
                    tail[2].clone(),
                    tail[3].clone(),
                    site.callable_receiver_origin()
                        .map_or(Value::Null, |origin| Value::Text(origin.label().to_owned())),
                ],
            );
        }
        let mut ordinals: HashMap<(i64, i64, i64), i64> = HashMap::default();
        for gap in lowered.lexical().gaps() {
            let (covers, subject, lookup) =
                gap_address(&mut coded, &mut interner, &keys, identities, gap);
            let ordinal = ordinals.entry((covers, subject, lookup)).or_insert(0);
            let gap_ordinal = *ordinal;
            *ordinal += 1;
            let (reason_kind, boundary_status) = gap.origin().completion_reason();
            let reason = Value::Integer(keys.semantic(gap.reason_semantic()));
            let site = Value::Integer(i64::from(gap.site().get()));
            let head = [
                Value::Integer(blob_id),
                Value::Integer(covers),
                Value::Integer(subject),
                Value::Integer(lookup),
                Value::Integer(gap_ordinal),
            ];
            coded.push(
                GAPS,
                &[
                    head[0].clone(),
                    head[1].clone(),
                    head[2].clone(),
                    head[3].clone(),
                    head[4].clone(),
                    Value::Integer(code(ALL_RESOLUTION_COMPLETION_REASON_KINDS, reason_kind)),
                    reason.clone(),
                    boundary_status.map_or(Value::Null, |status| {
                        Value::Integer(code(ALL_BOUNDARY_STATUSES, status))
                    }),
                    site.clone(),
                    Value::Integer(code(ALL_RESOLUTION_GAP_ORIGIN_KINDS, gap.origin().kind())),
                ],
            );
            labelled.push(
                GAPS,
                &[
                    head[0].clone(),
                    Value::Text(covers_label(covers).to_owned()),
                    head[2].clone(),
                    head[3].clone(),
                    head[4].clone(),
                    Value::Text(reason_kind.label().to_owned()),
                    reason,
                    boundary_status
                        .map_or(Value::Null, |status| Value::Text(status.label().to_owned())),
                    site,
                    Value::Text(gap.origin().kind().label().to_owned()),
                ],
            );
        }
        for db in [&mut coded, &mut labelled] {
            db.flush_all();
            db.transact("COMMIT");
            db.end_blob();
        }
    }
    let wall = started.elapsed();
    for (name, db) in [("enum_code", &mut coded), ("enum_text", &mut labelled)] {
        db.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");
        eprintln!(
            "[ld] enums={name} sites={} gaps={} identities={} write_s={:.1} wall_s={:.1}",
            db.sinks[SITES].rows,
            db.sinks[GAPS].rows,
            db.sinks[IDENTITIES].rows,
            db.write_time.as_secs_f64(),
            wall.as_secs_f64()
        );
    }
}

const fn covers_label(covers: i64) -> &'static str {
    match covers {
        0 => "fragment",
        1 => "enumeration",
        2 => "forward_inventory",
        3 => "reverse_inventory",
        4 => "reference",
        5 => "forward_candidate",
        6 => "reverse_candidate",
        7 => "type_frontier",
        _ => panic!("a gap covers one of the eight frontiers"),
    }
}

/// The committed DDL must stay loadable in every variant without running the
/// corpus pass, which takes minutes.
#[test]
fn draft_schema_loads_in_every_variant() {
    for (sections, foreign_keys) in [
        (&["core", "draft"][..], false),
        (&["core", "fk_parents", "draft"][..], true),
        (&["core", "enum_code"][..], false),
        (&["core", "enum_text"][..], false),
    ] {
        let conn = Connection::open_in_memory().expect("in-memory database");
        conn.execute_batch(&schema_text(sections, foreign_keys))
            .unwrap_or_else(|error| panic!("{sections:?} foreign_keys={foreign_keys}: {error}"));
    }
}
