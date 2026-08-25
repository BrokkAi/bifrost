use std::any::Any;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, LazyLock, LockResult, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;

use rusqlite::Connection;

use super::{
    GenerationId, PersistBatchLimits, PreparedParsedBlob, PreparedPersistenceWriter,
    PreparedWriteCounters, StoreError, reader_source_path,
};

const WRITER_QUEUE_CAPACITY: usize = 64;

type WriterJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
type WriterSlot = Arc<Mutex<Weak<PersistentWriter>>>;

enum WriterMessage {
    Execute(WriterJob),
    Repair(Box<RepairRequest>),
}

struct RepairRequest {
    prepared: PreparedParsedBlob,
    counters: PreparedWriteCounters,
    reply: SyncSender<Result<(), StoreError>>,
}

struct RepairGroup {
    prepared: PreparedParsedBlob,
    replies: Vec<SyncSender<Result<(), StoreError>>>,
}

static PERSISTENT_WRITERS: LazyLock<Mutex<HashMap<PathBuf, WriterSlot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
static NEXT_WRITER_ID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static ON_ANALYZER_WRITER_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// The writable side of one analyzer store.
///
/// Persistent stores share a process-local actor for their canonical cache
/// path. Ephemeral stores retain a local mutex because their backing database
/// is unique, and because the in-memory fallback must route reads through the
/// same connection.
pub(super) enum StoreWriter {
    Local(Mutex<Connection>),
    Persistent(Arc<PersistentWriter>),
}

impl StoreWriter {
    pub(super) fn local(conn: Connection) -> Self {
        Self::Local(Mutex::new(conn))
    }

    pub(super) fn persistent(db_path: &Path) -> Result<(Self, PathBuf), StoreError> {
        let registry_key = writer_registry_key(db_path)?;
        let slot = {
            let mut writers = PERSISTENT_WRITERS
                .lock()
                .expect("persistent analyzer writer registry poisoned");
            Arc::clone(
                writers
                    .entry(registry_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(Weak::new()))),
            )
        };

        // Opening and migrating SQLite belongs under the per-path slot. The
        // global registry lock is already released, so unrelated repositories
        // can initialize their writers concurrently.
        let mut registered = slot
            .lock()
            .expect("persistent analyzer writer slot poisoned");
        if let Some(writer) = registered.upgrade() {
            let reader_source = writer.reader_source.clone();
            return Ok((Self::Persistent(writer), reader_source));
        }

        let conn = crate::cache_db::open_unified_connection(db_path).map_err(StoreError::new)?;
        let reader_source = reader_source_path(&conn).unwrap_or_else(|| registry_key.clone());
        let writer = Arc::new(PersistentWriter::spawn(
            registry_key,
            reader_source.clone(),
            conn,
        )?);
        *registered = Arc::downgrade(&writer);
        Ok((Self::Persistent(writer), reader_source))
    }

    pub(super) fn execute<T, F>(&self, job: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> T + Send + 'static,
    {
        match self {
            Self::Local(conn) => {
                let mut conn = conn.lock().expect("analyzer store mutex poisoned");
                job(&mut conn)
            }
            Self::Persistent(writer) => writer.execute(job),
        }
    }

    pub(super) fn repair_prepared_blob(
        &self,
        prepared: PreparedParsedBlob,
        counters: PreparedWriteCounters,
    ) -> Result<(), StoreError> {
        match self {
            Self::Local(conn) => {
                let mut conn = conn.lock().expect("analyzer store mutex poisoned");
                persist_one_repair(&mut conn, prepared, counters)
            }
            Self::Persistent(writer) => writer.repair_prepared_blob(prepared, counters),
        }
    }

    /// Local-connection access for the in-memory reader fallback and existing
    /// ephemeral-store SQL tests. Persistent callers must use `execute`.
    pub(super) fn lock(&self) -> LockResult<MutexGuard<'_, Connection>> {
        match self {
            Self::Local(conn) => conn.lock(),
            Self::Persistent(_) => {
                panic!("persistent analyzer connections are owned by the writer actor")
            }
        }
    }

    #[cfg(test)]
    pub(super) fn identity(&self) -> usize {
        match self {
            Self::Local(conn) => conn as *const Mutex<Connection> as usize,
            Self::Persistent(writer) => writer.test_id,
        }
    }

    #[cfg(test)]
    pub(super) fn repair_submissions(&self) -> usize {
        match self {
            Self::Local(_) => 0,
            Self::Persistent(writer) => writer.repair_submissions.load(Ordering::SeqCst),
        }
    }

    #[cfg(test)]
    pub(super) fn repair_transactions(&self) -> usize {
        match self {
            Self::Local(_) => 0,
            Self::Persistent(writer) => writer.repair_transactions.load(Ordering::SeqCst),
        }
    }
}

pub(super) struct PersistentWriter {
    registry_key: PathBuf,
    reader_source: PathBuf,
    sender: Mutex<Option<SyncSender<WriterMessage>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    #[cfg(test)]
    repair_submissions: AtomicUsize,
    #[cfg(test)]
    repair_transactions: Arc<AtomicUsize>,
    #[cfg(test)]
    test_id: usize,
}

impl PersistentWriter {
    fn spawn(
        registry_key: PathBuf,
        reader_source: PathBuf,
        mut conn: Connection,
    ) -> Result<Self, StoreError> {
        let (sender, receiver) = sync_channel::<WriterMessage>(WRITER_QUEUE_CAPACITY);
        let thread_path = registry_key.clone();
        #[cfg(test)]
        let repair_transactions = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let thread_repair_transactions = Arc::clone(&repair_transactions);
        let thread = std::thread::Builder::new()
            .name("bifrost-analyzer-writer".to_string())
            .spawn(move || {
                ON_ANALYZER_WRITER_THREAD.with(|active| active.set(true));
                let mut pending = VecDeque::new();
                loop {
                    let message = match pending.pop_front() {
                        Some(message) => message,
                        None => match receiver.recv() {
                            Ok(message) => message,
                            Err(_) => break,
                        },
                    };
                    match message {
                        WriterMessage::Execute(job) => job(&mut conn),
                        WriterMessage::Repair(first) => {
                            let mut batch = RepairBatch::new(first);
                            loop {
                                match receiver.try_recv() {
                                    Ok(WriterMessage::Repair(request)) => {
                                        if let Err(request) = batch.try_push(request) {
                                            pending.push_back(WriterMessage::Repair(request));
                                            break;
                                        }
                                    }
                                    Ok(message @ WriterMessage::Execute(_)) => {
                                        pending.push_back(message);
                                        break;
                                    }
                                    Err(TryRecvError::Empty) => break,
                                    Err(TryRecvError::Disconnected) => break,
                                }
                            }
                            let transactions = batch.persist(&mut conn);
                            #[cfg(test)]
                            thread_repair_transactions.fetch_add(transactions, Ordering::SeqCst);
                            #[cfg(not(test))]
                            let _ = transactions;
                        }
                    }
                }
                ON_ANALYZER_WRITER_THREAD.with(|active| active.set(false));
            })
            .map_err(|error| {
                StoreError::new(format!(
                    "starting analyzer writer for {}: {error}",
                    thread_path.display()
                ))
            })?;
        Ok(Self {
            registry_key,
            reader_source,
            sender: Mutex::new(Some(sender)),
            thread: Mutex::new(Some(thread)),
            #[cfg(test)]
            repair_submissions: AtomicUsize::new(0),
            #[cfg(test)]
            repair_transactions,
            #[cfg(test)]
            test_id: NEXT_WRITER_ID.fetch_add(1, Ordering::SeqCst),
        })
    }

    fn execute<T, F>(&self, job: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> T + Send + 'static,
    {
        ON_ANALYZER_WRITER_THREAD.with(|active| {
            assert!(
                !active.get(),
                "analyzer writer jobs must not synchronously submit another writer job"
            );
        });
        let (reply_tx, reply_rx) = sync_channel::<Result<T, Box<dyn Any + Send>>>(1);
        let envelope: WriterJob = Box::new(move |conn| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(conn)));
            let _ = reply_tx.send(outcome);
        });
        let sender = self
            .sender
            .lock()
            .expect("persistent analyzer writer sender poisoned")
            .as_ref()
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "persistent analyzer writer is closed for {}",
                    self.registry_key.display()
                )
            });
        sender
            .send(WriterMessage::Execute(envelope))
            .unwrap_or_else(|_| {
                panic!(
                    "persistent analyzer writer disconnected for {}",
                    self.registry_key.display()
                )
            });
        match reply_rx.recv() {
            Ok(Ok(value)) => value,
            Ok(Err(payload)) => std::panic::resume_unwind(payload),
            Err(_) => panic!(
                "persistent analyzer writer dropped a reply for {}",
                self.registry_key.display()
            ),
        }
    }

    fn repair_prepared_blob(
        &self,
        prepared: PreparedParsedBlob,
        counters: PreparedWriteCounters,
    ) -> Result<(), StoreError> {
        let (reply, result) = sync_channel(1);
        let sender = self
            .sender
            .lock()
            .expect("persistent analyzer writer sender poisoned")
            .as_ref()
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "persistent analyzer writer is closed for {}",
                    self.registry_key.display()
                )
            });
        sender
            .send(WriterMessage::Repair(Box::new(RepairRequest {
                prepared,
                counters,
                reply,
            })))
            .unwrap_or_else(|_| {
                panic!(
                    "persistent analyzer writer disconnected for {}",
                    self.registry_key.display()
                )
            });
        #[cfg(test)]
        self.repair_submissions.fetch_add(1, Ordering::SeqCst);
        result.recv().unwrap_or_else(|_| {
            panic!(
                "persistent analyzer writer dropped a repair reply for {}",
                self.registry_key.display()
            )
        })
    }
}

struct RepairBatch {
    groups: Vec<RepairGroup>,
    by_key: HashMap<(git2::Oid, String, GenerationId), usize>,
    generations_by_blob: HashMap<(git2::Oid, String), GenerationId>,
    rows: usize,
    bytes: usize,
    counters: PreparedWriteCounters,
}

impl RepairBatch {
    fn new(first: Box<RepairRequest>) -> Self {
        let first = *first;
        let rows = first.prepared.mutation_logical_rows();
        let bytes = first.prepared.mutation_payload_bytes();
        let key = repair_key(&first.prepared);
        let blob_key = (key.0, key.1.clone());
        let mut by_key = HashMap::new();
        by_key.insert(key.clone(), 0);
        let mut generations_by_blob = HashMap::new();
        generations_by_blob.insert(blob_key, key.2);
        Self {
            groups: vec![RepairGroup {
                prepared: first.prepared,
                replies: vec![first.reply],
            }],
            by_key,
            generations_by_blob,
            rows,
            bytes,
            counters: first.counters,
        }
    }

    fn try_push(&mut self, request: Box<RepairRequest>) -> Result<(), Box<RepairRequest>> {
        let key = repair_key(&request.prepared);
        if let Some(&group) = self.by_key.get(&key) {
            self.groups[group].replies.push(request.reply);
            return Ok(());
        }
        let blob_key = (key.0, key.1.clone());
        if self
            .generations_by_blob
            .get(&blob_key)
            .is_some_and(|generation| *generation != key.2)
        {
            return Err(request);
        }

        let limits = PersistBatchLimits::PRODUCTION;
        let rows = request.prepared.mutation_logical_rows();
        let bytes = request.prepared.mutation_payload_bytes();
        if self.groups.len() >= limits.max_blobs
            || self.rows.saturating_add(rows) > limits.max_rows
            || self.bytes.saturating_add(bytes) > limits.max_payload_bytes
        {
            return Err(request);
        }

        let group = self.groups.len();
        self.by_key.insert(key.clone(), group);
        self.generations_by_blob.insert(blob_key, key.2);
        self.groups.push(RepairGroup {
            prepared: request.prepared,
            replies: vec![request.reply],
        });
        self.rows = self.rows.saturating_add(rows);
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    fn persist(self, conn: &mut Connection) -> usize {
        let mut prepared = Vec::with_capacity(self.groups.len());
        let mut grouped_replies = Vec::with_capacity(self.groups.len());
        for group in self.groups {
            prepared.push(group.prepared);
            grouped_replies.push(group.replies);
        }
        let (outcomes, stats) = PreparedPersistenceWriter::new(conn, self.counters)
            .persist_prepared_blobs(prepared, PersistBatchLimits::PRODUCTION);
        assert_eq!(
            outcomes.len(),
            grouped_replies.len(),
            "each repair representative must retain its reply group"
        );
        for (outcome, replies) in outcomes.into_iter().zip(grouped_replies) {
            let result = outcome.error.map_or(Ok(()), Err);
            for reply in replies {
                let _ = reply.send(result.clone());
            }
        }
        stats.transactions
    }
}

fn persist_one_repair(
    conn: &mut Connection,
    prepared: PreparedParsedBlob,
    counters: PreparedWriteCounters,
) -> Result<(), StoreError> {
    let (mut outcomes, _) = PreparedPersistenceWriter::new(conn, counters)
        .persist_prepared_blobs(vec![prepared], PersistBatchLimits::PRODUCTION);
    outcomes
        .pop()
        .expect("one prepared repair has one outcome")
        .error
        .map_or(Ok(()), Err)
}

fn repair_key(prepared: &PreparedParsedBlob) -> (git2::Oid, String, GenerationId) {
    (
        prepared.oid(),
        prepared.lang().to_string(),
        prepared.generation,
    )
}

impl Drop for PersistentWriter {
    fn drop(&mut self) {
        self.sender
            .get_mut()
            .expect("persistent analyzer writer sender poisoned")
            .take();
        if let Some(thread) = self
            .thread
            .get_mut()
            .expect("persistent analyzer writer thread lock poisoned")
            .take()
        {
            thread.join().unwrap_or_else(|payload| {
                std::panic::resume_unwind(payload);
            });
        }
    }
}

fn writer_registry_key(db_path: &Path) -> Result<PathBuf, StoreError> {
    let absolute = if db_path.is_absolute() {
        db_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| StoreError::new(format!("reading current directory: {error}")))?
            .join(db_path)
    };
    let Some(file_name) = absolute.file_name() else {
        return Err(StoreError::new(format!(
            "analyzer cache path has no file name: {}",
            absolute.display()
        )));
    };
    Ok(absolute
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .map(|parent| parent.join(file_name))
        .unwrap_or(absolute))
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{TryRecvError, sync_channel};

    use super::StoreWriter;

    #[test]
    fn persistent_stores_for_one_path_share_one_actor() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let (first, _) = StoreWriter::persistent(&db).unwrap();
        let (second, _) = StoreWriter::persistent(&db).unwrap();
        assert_eq!(first.identity(), second.identity());

        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let blocker = std::thread::spawn(move || {
            first.execute(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        entered_rx.recv().unwrap();

        let (completed_tx, completed_rx) = sync_channel(1);
        let follower = std::thread::spawn(move || {
            second.execute(move |_| completed_tx.send(()).unwrap());
        });
        assert_eq!(completed_rx.try_recv(), Err(TryRecvError::Empty));
        release_tx.send(()).unwrap();
        completed_rx.recv().unwrap();
        blocker.join().unwrap();
        follower.join().unwrap();
    }

    #[test]
    fn different_cache_paths_have_independent_actors() {
        let temp = tempfile::TempDir::new().unwrap();
        let (first, _) = StoreWriter::persistent(&temp.path().join("a.db")).unwrap();
        let (second, _) = StoreWriter::persistent(&temp.path().join("b.db")).unwrap();
        assert_ne!(first.identity(), second.identity());

        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let blocker = std::thread::spawn(move || {
            first.execute(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        entered_rx.recv().unwrap();

        let (completed_tx, completed_rx) = sync_channel(1);
        second.execute(move |_| completed_tx.send(()).unwrap());
        completed_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        blocker.join().unwrap();
    }

    #[test]
    fn panicking_caller_does_not_kill_shared_actor() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let (writer, _) = StoreWriter::persistent(&db).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.execute::<(), _>(|_| panic!("injected writer job panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(writer.execute(|_| 42), 42);
    }

    #[test]
    fn dropping_the_last_handle_stops_the_actor_before_reopen() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let first_id = {
            let (writer, _) = StoreWriter::persistent(&db).unwrap();
            assert_eq!(writer.execute(|_| 41), 41);
            writer.identity()
        };

        let (reopened, _) = StoreWriter::persistent(&db).unwrap();
        assert_ne!(first_id, reopened.identity());
        assert_eq!(reopened.execute(|_| 42), 42);
    }
}
