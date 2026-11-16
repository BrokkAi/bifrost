//! Reader-private pristine macro-front transitions. No retained SQLite backing.
use super::*;
use brokk_bifrost_core::retention_budget::{RetainedBytes, SharedBackingLease};
use rusqlite::types::{ToSqlOutput, ValueRef};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct MacroFrontKey {
    pub requested_files: Vec<PathBuf>,
    pub selection_fingerprint: [u8; 32],
    pub routing_digest: [u8; 32],
    pub scope_identity: [u8; 32],
    pub analysis_generation: u64,
    pub main_data_version: i64,
}

impl RetainedBytes for MacroFrontKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self) + self.requested_files.retained_bytes()
            - std::mem::size_of_val(&self.requested_files)
    }
}

// A fixed-size, budgeted observation for miss diagnostics, never answer validation.
#[derive(Clone)]
struct KeyWitness {
    generation: u64,
    data_version: i64,
    selection: [u8; 32],
    routing: [u8; 32],
    scope: [u8; 32],
    files: [u8; 32],
}
impl KeyWitness {
    fn from_key(key: &MacroFrontKey) -> Self {
        let mut files = CanonicalHasher::new(b"macro-front-observed-files:v1");
        for path in &key.requested_files {
            files.value(path.as_os_str().as_encoded_bytes());
        }
        Self {
            generation: key.analysis_generation,
            data_version: key.main_data_version,
            selection: key.selection_fingerprint,
            routing: key.routing_digest,
            scope: key.scope_identity,
            files: files.finish(),
        }
    }
    fn difference(&self, current: &Self) -> &'static str {
        if self.generation != current.generation {
            "generation"
        } else if self.data_version != current.data_version {
            "data_version"
        } else if self.selection != current.selection {
            "selection"
        } else if self.routing != current.routing {
            "routing"
        } else if self.scope != current.scope {
            "scope"
        } else if self.files != current.files {
            "file_set"
        } else {
            "not_resident"
        }
    }
}
impl RetainedBytes for KeyWitness {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}

/// A fresh namespace belongs to one physical reader: data_version is local.
/// The guard releases every optional resident when the reader is discarded.
pub(in crate::analyzer::store) struct RetainedMacroFrontier {
    pub(super) region: BudgetRegion<MacroFrontKey, MacroFrontOutput>,
    pub(super) main_data_version: Option<i64>,
    witness: BudgetRegion<u8, KeyWitness>,
}
impl RetainedMacroFrontier {
    pub(in crate::analyzer::store) fn new(budget: &RetentionBudget) -> Self {
        Self {
            region: budget.region("rust_macro_fronts", None),
            main_data_version: None,
            witness: budget.region("rust_macro_front_observation", Some(1)),
        }
    }
    pub(super) fn miss_reason(&self, key: &MacroFrontKey) -> &'static str {
        self.witness
            .get(&0)
            .map_or("no_resident_witness", |previous| {
                previous.difference(&KeyWitness::from_key(key))
            })
    }
    pub(super) fn observe_key(&self, key: &MacroFrontKey) {
        self.witness.insert(0, KeyWitness::from_key(key));
    }
}
impl Drop for RetainedMacroFrontier {
    fn drop(&mut self) {
        self.region.invalidate_all();
        self.witness.invalidate_all();
    }
}

// One contiguous byte buffer per table, rather than one allocation per cell.
#[derive(Clone, Copy)]
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text { start: usize, len: usize },
    Blob { start: usize, len: usize },
}
struct Table {
    name: String,
    columns: usize,
    cells: Vec<Cell>,
    bytes: Vec<u8>,
}
struct BoundCell<'a> {
    cell: Cell,
    bytes: &'a [u8],
}
impl rusqlite::ToSql for BoundCell<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(match self.cell {
            Cell::Null => ValueRef::Null,
            Cell::Integer(value) => ValueRef::Integer(value),
            Cell::Real(value) => ValueRef::Real(value),
            Cell::Text { start, len } => ValueRef::Text(&self.bytes[start..start + len]),
            Cell::Blob { start, len } => ValueRef::Blob(&self.bytes[start..start + len]),
        }))
    }
}
struct TableLayout {
    name: String,
    columns: usize,
    cells: usize,
    bytes: usize,
}
impl TableLayout {
    fn measure(connection: &rusqlite::Connection, name: String) -> Result<Self> {
        let statement = connection.prepare(&format!("SELECT * FROM temp.{name}"))?;
        let columns = statement.column_count();
        let lengths = statement.column_names().into_iter().map(|column| {
            assert!(column.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'), "stage columns are trusted schema identifiers");
            format!("CASE WHEN typeof(\"{column}\") IN ('text','blob') THEN length(CAST(\"{column}\" AS BLOB)) ELSE 0 END")
        }).collect::<Vec<_>>().join("+");
        let (rows, bytes): (usize, usize) = connection.query_row(
            &format!("SELECT count(*),coalesce(sum({lengths}),0) FROM temp.{name}"),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let cells = rows
            .checked_mul(columns)
            .ok_or_else(|| StoreError::new("macro front cell size overflow"))?;
        Ok(Self {
            name,
            columns,
            cells,
            bytes,
        })
    }
    fn retained_bytes(&self) -> Option<usize> {
        self.cells
            .checked_mul(std::mem::size_of::<Cell>())?
            .checked_add(self.bytes)?
            .checked_add(self.name.capacity())
    }
    fn capture(self, connection: &rusqlite::Connection) -> Result<Table> {
        let mut statement = connection.prepare(&format!("SELECT * FROM temp.{}", self.name))?;
        let mut table = Table {
            name: self.name,
            columns: self.columns,
            cells: Vec::with_capacity(self.cells),
            bytes: Vec::with_capacity(self.bytes),
        };
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            for column in 0..table.columns {
                let cell = match row.get_ref(column)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Integer(value),
                    ValueRef::Real(value) => Cell::Real(value),
                    value @ (ValueRef::Text(_) | ValueRef::Blob(_)) => {
                        let bytes = match value {
                            ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes,
                            _ => unreachable!(),
                        };
                        let start = table.bytes.len();
                        // The private TEMP stage cannot grow between measure and copy.
                        assert!(start + bytes.len() <= self.bytes);
                        table.bytes.extend_from_slice(bytes);
                        if matches!(value, ValueRef::Text(_)) {
                            Cell::Text {
                                start,
                                len: bytes.len(),
                            }
                        } else {
                            Cell::Blob {
                                start,
                                len: bytes.len(),
                            }
                        }
                    }
                };
                assert!(table.cells.len() < self.cells);
                table.cells.push(cell);
            }
        }
        assert_eq!(table.cells.len(), self.cells);
        assert_eq!(table.bytes.len(), self.bytes);
        Ok(table)
    }
}

struct StageSnapshot {
    tables: Vec<Table>,
    // Reservation starts before any row buffers are allocated and follows their final drop.
    backing: SharedBackingLease,
}
impl StageSnapshot {
    fn capture(
        connection: &rusqlite::Connection,
        budget: &RetentionBudget,
        extra_bytes: usize,
    ) -> Result<Option<Self>> {
        let layouts = macro_stage_tables(connection)?
            .into_iter()
            .map(|name| TableLayout::measure(connection, name))
            .collect::<Result<Vec<_>>>()?;
        // The table vector is charged at its allocation size, as
        // `Vec::retained_bytes` reports it.
        let mut bytes = layouts
            .len()
            .checked_mul(std::mem::size_of::<Table>())
            .map(brokk_bifrost_core::allocation_size::allocation_size)
            .and_then(|bytes| bytes.checked_add(extra_bytes));
        for layout in &layouts {
            bytes = bytes.and_then(|bytes| bytes.checked_add(layout.retained_bytes()?));
        }
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let Some(backing) = budget.shared_backing(bytes as u64) else {
            return Ok(None);
        };
        let mut tables = Vec::with_capacity(layouts.len());
        for layout in layouts {
            tables.push(layout.capture(connection)?);
        }
        Ok(Some(Self { tables, backing }))
    }
}

impl Table {
    fn restore(&self, connection: &rusqlite::Connection) -> Result<()> {
        let placeholders = std::iter::repeat_n("?", self.columns)
            .collect::<Vec<_>>()
            .join(",");
        let mut insert = connection.prepare_cached(&format!(
            "INSERT INTO temp.{} VALUES ({placeholders})",
            self.name
        ))?;
        for row in self.cells.chunks_exact(self.columns) {
            insert.execute(rusqlite::params_from_iter(row.iter().map(|&cell| {
                BoundCell {
                    cell,
                    bytes: &self.bytes,
                }
            })))?;
        }
        Ok(())
    }
}
impl RetainedBytes for Table {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.name.capacity()
            + self.cells.capacity() * std::mem::size_of::<Cell>()
            + self.bytes.capacity()
    }
}

pub(super) struct MacroFrontOutput {
    pub checked_files: HashSet<PathBuf>,
    pub overlay: MacroOverlaySlot,
    pub prepared_files: HashSet<PathBuf>,
    pub receipt: Box<dyn std::any::Any + Send + Sync>,
    receipt_bytes: usize,
    // Last: release the reservation only after every charged allocation drops.
    stage: StageSnapshot,
}
impl MacroFrontOutput {
    pub(super) fn capture(
        operation: &SelectedResolutionOperation<'_, '_>,
        receipt: Box<dyn std::any::Any + Send + Sync>,
        reads: &dyn SelectedMacroFrontierReads,
    ) -> Result<Option<Self>> {
        use brokk_bifrost_core::hash::set_slot_bytes;
        let receipt_bytes = reads.receipt_bytes(receipt.as_ref());
        let checked = operation.ready.checked_macro_frontier_files.borrow();
        let prepared = operation.ready.prepared_macro_files.borrow();
        let overlay = operation.ready.macro_overlay.borrow();
        let extra_bytes = receipt_bytes
            + set_slot_bytes(&checked)
            + set_slot_bytes(&prepared)
            + set_slot_bytes(&overlay.prepared_files)
            + checked
                .iter()
                .chain(prepared.iter())
                .map(PathBuf::capacity)
                .sum::<usize>()
            + overlay
                .prepared_files
                .iter()
                .map(String::capacity)
                .sum::<usize>();
        let Some(stage) = StageSnapshot::capture(
            operation.ready.inventory.connection(),
            operation.ready.store.retention_budget(),
            extra_bytes,
        )?
        else {
            return Ok(None);
        };
        let output = Self {
            stage,
            checked_files: checked.clone(),
            prepared_files: prepared.clone(),
            overlay: overlay.clone(),
            receipt_bytes,
            receipt,
        };
        assert!(output.payload_bytes() as u64 <= output.stage.backing.bytes());
        Ok(Some(output))
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn state_digest(
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> Result<[u8; 32]> {
        // Only small in-tree test fixtures request this independent observation.
        let connection = operation.ready.inventory.connection();
        let tables = macro_stage_tables(connection)?
            .into_iter()
            .map(|name| TableLayout::measure(connection, name)?.capture(connection))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::digest(
            &tables,
            &operation.ready.checked_macro_frontier_files.borrow(),
            &operation.ready.prepared_macro_files.borrow(),
            &operation.ready.macro_overlay.borrow(),
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn digest(
        tables: &[Table],
        checked_files: &HashSet<PathBuf>,
        prepared_files: &HashSet<PathBuf>,
        overlay: &MacroOverlaySlot,
    ) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-pristine-macro-front-output:v1");
        let mut tables = tables
            .iter()
            .filter(|table| !table.cells.is_empty())
            .collect::<Vec<_>>();
        tables.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        for table in tables {
            hash.value(table.name.as_bytes());
            hash.value(&(table.columns as u64).to_be_bytes());
            let mut rows = Vec::new();
            for cells in table.cells.chunks_exact(table.columns) {
                let mut row = CanonicalHasher::new(b"bifrost-macro-front-row:v1");
                for &cell in cells {
                    match cell {
                        Cell::Null => row.value(&[0]),
                        Cell::Integer(value) => {
                            row.value(&[1]);
                            row.value(&value.to_be_bytes());
                        }
                        Cell::Real(value) => {
                            row.value(&[2]);
                            row.value(&value.to_bits().to_be_bytes());
                        }
                        Cell::Text { start, len } => {
                            row.value(&[3]);
                            row.value(&table.bytes[start..start + len]);
                        }
                        Cell::Blob { start, len } => {
                            row.value(&[4]);
                            row.value(&table.bytes[start..start + len]);
                        }
                    }
                }
                rows.push(row.finish());
            }
            rows.sort_unstable();
            hash.sequence("rows", &rows, |hash, row| hash.value(row));
        }
        for files in [checked_files, prepared_files] {
            let mut files = files.iter().collect::<Vec<_>>();
            files.sort_unstable();
            hash.value(&(files.len() as u64).to_be_bytes());
            for file in files {
                hash.value(file.as_os_str().as_encoded_bytes());
            }
        }
        let mut files = overlay.prepared_files.iter().collect::<Vec<_>>();
        files.sort_unstable();
        for file in files {
            hash.value(file.as_bytes());
        }
        hash.finish()
    }

    pub(super) fn reserved_bytes(&self) -> u64 {
        self.stage.backing.bytes()
    }

    pub(super) fn restore(&self, operation: &SelectedResolutionOperation<'_, '_>) -> Result<()> {
        assert!(
            operation.macro_front_is_pristine(),
            "front restoration requires pristine SQL and ready bookkeeping"
        );
        let inventory = &operation.ready.inventory;
        inventory.with_owned_temp_transaction(|connection| {
            for table in &self.stage.tables {
                table.restore(connection)?;
            }
            #[cfg(any(test, feature = "test-support"))]
            if FORCE_MACRO_RESTORE_FAILURE.with(std::cell::Cell::get) {
                MACRO_RESTORED_ROWS_FOR_TEST.with(|count| {
                    count.set(
                        self.stage
                            .tables
                            .iter()
                            .map(|table| table.cells.len() / table.columns)
                            .sum(),
                    )
                });
                return Err(StoreError::new("forced macro front restore failure"));
            }
            Ok(super::super::resolution_selection::SelectedResolutionTempTransaction::Commit(()))
        })?;
        inventory.note_restored_macro_stage();
        Ok(())
    }
}
impl MacroFrontOutput {
    fn payload_bytes(&self) -> usize {
        use brokk_bifrost_core::hash::set_slot_bytes;
        self.stage.tables.retained_bytes() - std::mem::size_of_val(&self.stage.tables)
            + self.receipt_bytes
            + set_slot_bytes(&self.checked_files)
            + self
                .checked_files
                .iter()
                .map(PathBuf::capacity)
                .sum::<usize>()
            + set_slot_bytes(&self.prepared_files)
            + self
                .prepared_files
                .iter()
                .map(PathBuf::capacity)
                .sum::<usize>()
            + set_slot_bytes(&self.overlay.prepared_files)
            + self
                .overlay
                .prepared_files
                .iter()
                .map(String::capacity)
                .sum::<usize>()
    }
}

impl RetainedBytes for MacroFrontOutput {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
    fn eviction_bytes(&self) -> usize {
        std::mem::size_of_val(self).saturating_add(self.stage.backing.bytes() as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11281: snapshot discard and copy reprobed every shadow table"
    )]
    fn owned_rows_survive_rolled_back_ddl_without_shadow_schema_probes() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TEMP TABLE selected_resolution_stage_probe(i INTEGER, r REAL, t TEXT, b BLOB, n); INSERT INTO selected_resolution_stage_probe VALUES(1, 0.25, char(233,0,120), x'00ff', NULL)").unwrap();
        let table = TableLayout::measure(&connection, "selected_resolution_stage_probe".to_owned())
            .unwrap()
            .capture(&connection)
            .unwrap();
        connection.execute_batch("SAVEPOINT alter_stage; DROP TABLE selected_resolution_stage_probe; ROLLBACK TO alter_stage; RELEASE alter_stage; DELETE FROM selected_resolution_stage_probe").unwrap();
        table.restore(&connection).unwrap();
        let values: (i64, f64, String, Vec<u8>, Option<i64>) = connection
            .query_row("SELECT * FROM selected_resolution_stage_probe", [], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap();
        assert_eq!(
            values,
            (1, 0.25, "\u{e9}\0x".to_owned(), vec![0, 255], None)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM temp.sqlite_schema WHERE name LIKE 'retained_macro_%'",
                    [],
                    |row| row.get::<_, usize>(0)
                )
                .unwrap(),
            0
        );
        connection
            .execute_batch("UPDATE selected_resolution_stage_probe SET i=2")
            .unwrap();
        let newer = TableLayout::measure(&connection, "selected_resolution_stage_probe".to_owned())
            .unwrap()
            .capture(&connection)
            .unwrap();
        connection
            .execute_batch("DELETE FROM selected_resolution_stage_probe")
            .unwrap();
        newer.restore(&connection).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT i FROM selected_resolution_stage_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            2,
            "each capture sees current rows without a stale schema inventory"
        );
    }

    #[test]
    fn oversized_front_is_not_retained_and_does_not_allocate_shadow_pages() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TEMP TABLE selected_resolution_stage_probe(payload BLOB); INSERT INTO selected_resolution_stage_probe VALUES(zeroblob(17000000))").unwrap();
        let pages = || {
            connection
                .query_row("PRAGMA temp.page_count", [], |row| row.get::<_, i64>(0))
                .unwrap()
        };
        let before = pages();
        let budget = RetentionBudget::for_test_capacity(1024);
        let snapshot = StageSnapshot::capture(&connection, &budget, 0).unwrap();
        assert!(
            snapshot.is_none(),
            "oversized front is refused before allocating row buffers"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT length(payload) FROM selected_resolution_stage_probe",
                    [],
                    |row| row.get::<_, usize>(0)
                )
                .unwrap(),
            17000000,
            "refused optional retention preserves the full query stage"
        );
        assert_eq!(
            pages(),
            before,
            "capture never allocates SQLite shadow pages"
        );
        assert_eq!(budget.accounted_bytes(), 0);
    }
}

#[cfg(test)]
mod construction_tests {
    use super::*;

    #[test]
    fn overlapping_snapshot_construction_shares_the_owner_allowance() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TEMP TABLE selected_resolution_stage_probe(payload BLOB); INSERT INTO selected_resolution_stage_probe VALUES(zeroblob(65536))").unwrap();
        let layout =
            TableLayout::measure(&connection, "selected_resolution_stage_probe".to_owned())
                .unwrap();
        let needed =
            brokk_bifrost_core::allocation_size::allocation_size(std::mem::size_of::<Table>())
                + layout.retained_bytes().unwrap();
        let budget = RetentionBudget::for_test_capacity(needed as u64);
        let first = StageSnapshot::capture(&connection, &budget, 0)
            .unwrap()
            .unwrap();
        assert_eq!(budget.accounted_bytes(), needed as u64);
        assert!(
            StageSnapshot::capture(&connection, &budget, 0)
                .unwrap()
                .is_none(),
            "another in-flight copy cannot exceed the same owner allowance"
        );
        drop(first);
        assert_eq!(budget.accounted_bytes(), 0);
        let second = StageSnapshot::capture(&connection, &budget, 0)
            .unwrap()
            .unwrap();
        assert_eq!(second.tables[0].bytes.len(), 65536);
        drop(second);
        assert_eq!(budget.accounted_bytes(), 0);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    fn key() -> MacroFrontKey {
        MacroFrontKey {
            requested_files: vec![PathBuf::from("src/lib.rs")],
            selection_fingerprint: [1; 32],
            routing_digest: [2; 32],
            scope_identity: [3; 32],
            analysis_generation: 1,
            main_data_version: 1,
        }
    }
    fn output(connection: &rusqlite::Connection, budget: &RetentionBudget) -> MacroFrontOutput {
        MacroFrontOutput {
            checked_files: HashSet::default(),
            prepared_files: HashSet::default(),
            overlay: MacroOverlaySlot::default(),
            receipt: Box::new(()),
            receipt_bytes: 0,
            stage: StageSnapshot::capture(connection, budget, 0)
                .unwrap()
                .unwrap(),
        }
    }
    fn connection() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TEMP TABLE selected_resolution_stage_probe(value INTEGER); INSERT INTO selected_resolution_stage_probe VALUES(7)").unwrap();
        connection
    }
    #[test]
    fn each_authority_change_misses_the_retained_fixture_and_names_its_reason() {
        let connection = connection();
        let budget = RetentionBudget::for_tests();
        let owner = RetainedMacroFrontier::new(&budget);
        let original = key();
        owner.observe_key(&original);
        owner
            .region
            .insert(original.clone(), output(&connection, &budget));
        type AuthorityChange = (&'static str, fn(&mut MacroFrontKey));
        let cases: [AuthorityChange; 6] = [
            ("generation", |key| key.analysis_generation += 1),
            ("data_version", |key| key.main_data_version += 1),
            ("selection", |key| key.selection_fingerprint = [4; 32]),
            ("routing", |key| key.routing_digest = [4; 32]),
            ("scope", |key| key.scope_identity = [4; 32]),
            ("file_set", |key| {
                key.requested_files.push(PathBuf::from("src/other.rs"))
            }),
        ];
        for (reason, change) in cases {
            let mut current = original.clone();
            change(&mut current);
            assert!(
                owner.region.get(&current).is_none(),
                "{reason} cannot restore another authority's stage"
            );
            assert_eq!(owner.miss_reason(&current), reason);
            assert!(
                owner.region.get(&original).is_some(),
                "the original exact authority still works"
            );
        }
        drop(owner);
        budget.run_pending_tasks();
        assert_eq!(
            budget.accounted_bytes(),
            0,
            "reader disposal releases resident fronts and witness"
        );
    }
    #[test]
    fn held_front_keeps_its_payload_charged_after_eviction_and_reader_disposal() {
        let connection = connection();
        let budget = RetentionBudget::for_tests();
        let owner = RetainedMacroFrontier::new(&budget);
        let key = key();
        let value = output(&connection, &budget);
        let reserved = value.reserved_bytes();
        let held = match owner.region.insert(key.clone(), value) {
            BudgetedValue::Retained(value) => value,
            _ => panic!("fixture fits"),
        };
        let region = owner.region.clone();
        owner.region.invalidate_all();
        assert!(region.get(&key).is_none());
        drop(owner);
        assert!(
            budget.accounted_bytes() >= reserved,
            "eviction and owner drop cannot release held backing"
        );
        connection
            .execute_batch("DELETE FROM selected_resolution_stage_probe")
            .unwrap();
        held.stage.tables[0].restore(&connection).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM selected_resolution_stage_probe",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            7
        );
        drop(held);
        budget.run_pending_tasks();
        assert_eq!(
            budget.accounted_bytes(),
            0,
            "final held drop frees the payload reservation"
        );
    }
}
