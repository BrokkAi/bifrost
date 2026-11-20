//! One frozen SQLite authority for watcher certification and fact projection.
use super::*;

/// Request-local only. It never escapes the update's carry operation.
#[doc(hidden)]
pub struct UpdateProjectionRead<'a> {
    store: &'a AnalyzerStore,
    connection: ReaderGuard<'a>,
    failed: std::cell::Cell<bool>,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static PROJECTION_SQL_FAILURE: std::cell::Cell<(Option<&'static str>, bool)> = const { std::cell::Cell::new((None, false)) };
    static BOUNDED_READ_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn inject_projection_sql_failure(conn: &Connection, entries: &[BlobKey]) -> Result<()> {
    let (language, active) = PROJECTION_SQL_FAILURE.get();
    if active
        && entries
            .iter()
            .any(|key| language == Some(key.lang.as_str()))
    {
        // A real SQLite execution failure, restricted to the requested language.
        conn.execute_batch("SELECT abs(-9223372036854775808)")?;
    }
    Ok(())
}

impl AnalyzerStore {
    /// Start a language-local SQL fault only at bounded admission, after
    /// producer updates and certification metadata checks have succeeded.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_projection_sql_failure_for_test<T>(
        language: &'static str,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Reset((Option<&'static str>, bool));
        impl Drop for Reset {
            fn drop(&mut self) {
                PROJECTION_SQL_FAILURE.set(self.0);
            }
        }
        let _reset = Reset(PROJECTION_SQL_FAILURE.replace((Some(language), false)));
        operation()
    }

    /// Fail every bounded membership read on the frozen update connection and
    /// nothing else. The full path's reads on other connections are untouched,
    /// so this isolates a failure that only the bounded preparation sees.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_bounded_read_failure_for_test<T>(operation: impl FnOnce() -> T) -> T {
        struct Reset(bool);
        impl Drop for Reset {
            fn drop(&mut self) {
                BOUNDED_READ_FAILURE.set(self.0);
            }
        }
        let _reset = Reset(BOUNDED_READ_FAILURE.replace(true));
        operation()
    }

    #[doc(hidden)]
    pub fn begin_update_projection_read(&self) -> Result<UpdateProjectionRead<'_>> {
        let connection = self.checkout_read_conn()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        Ok(UpdateProjectionRead {
            store: self,
            connection,
            failed: std::cell::Cell::new(false),
        })
    }
}
impl Drop for UpdateProjectionRead<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.connection.execute_batch("ROLLBACK") {
            eprintln!("ending watcher projection read transaction: {error}");
        }
    }
}
impl UpdateProjectionRead<'_> {
    /// A failed bounded read forbids certification, even if a caller consumed
    /// the error to preserve the ordinary missing-fact representation.
    pub fn had_failure(&self) -> bool {
        self.failed.get()
    }
    fn observe<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub fn require_epoch(&self, language: &str, generation: GenerationId) -> Result<()> {
        let result = require_current_generation(&self.connection, language, generation);
        self.observe(result)
    }
    pub fn selected_set_complete(&self, snapshot: &WorkspaceSnapshotId) -> Result<bool> {
        let result = workspace_inputs::selected_set_complete(&self.connection, snapshot);
        self.observe(result)
    }
    pub fn parsed_blob_keys(
        &self,
        entries: &[BlobKey],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashSet<BlobKey>> {
        #[cfg(any(test, feature = "test-support"))]
        if PROJECTION_SQL_FAILURE.get().0.is_some() {
            PROJECTION_SQL_FAILURE.set((PROJECTION_SQL_FAILURE.get().0, true));
        }
        let result = (|| {
            #[cfg(any(test, feature = "test-support"))]
            if BOUNDED_READ_FAILURE.get() {
                // A real SQLite execution failure on the frozen connection only.
                self.connection
                    .execute_batch("SELECT abs(-9223372036854775808)")?;
            }
            #[cfg(any(test, feature = "test-support"))]
            self.store
                .parsed_blob_membership_keys
                .fetch_add(entries.len(), Ordering::SeqCst);
            require_generation_map(
                &self.connection,
                generations,
                entries.iter().map(|key| key.lang.as_str()),
            )?;
            parsed_blob_keys_conn(&self.connection, entries)
        })();
        self.observe(result)
    }
    pub fn selected_variants(
        &self,
        snapshot: &WorkspaceSnapshotId,
        paths: &[String],
    ) -> Result<Vec<Option<ParseVariant>>> {
        let result = (|| {
            let encoded = serde_json::to_string(paths).expect("path strings serialize");
            let mut statement=self.connection.prepare_cached("SELECT requested.key,(SELECT COALESCE(decisions.decision_digest,x'') FROM workspace_file_versions AS files LEFT JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id=files.file_version_id WHERE files.workspace_id=?1 AND files.lang=?2 AND files.generation=?3 AND files.input_kind='source' AND files.rel_path=requested.value AND files.valid_from<=?4 AND (files.valid_until IS NULL OR ?4<files.valid_until)) FROM json_each(?5) AS requested")?;
            let mut values = vec![None; paths.len()];
            for row in statement.query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.get(),
                    snapshot.revision,
                    encoded
                ],
                |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, Option<ParseVariant>>(1)?,
                    ))
                },
            )? {
                let (ordinal, value) = row?;
                values[ordinal] = value;
            }
            Ok(values)
        })();
        self.observe(result)
    }
    pub fn source_refused(
        &self,
        snapshot: &WorkspaceSnapshotId,
        path: &str,
        oid: Oid,
    ) -> Result<bool> {
        let result = (|| {
            Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM workspace_source_refusals WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND rel_path=?4 AND blob_oid=?5 AND valid_from<=?6 AND (valid_until IS NULL OR ?6<valid_until))",params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.get(),path,oid.to_string(),snapshot.revision],|row|row.get(0))?)
        })();
        self.observe(result)
    }
    pub fn hydrate<A: StoreLanguageAdapter>(
        &self,
        key: &BlobKey,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Option<FileState>> {
        let result = (|| {
            require_current_generation(&self.connection, &key.lang, generation)?;
            hydrate_file_state_conn(&self.connection, key, adapter, file, source)
        })();
        self.observe(result)
    }
    pub fn package_facts(
        &self,
        key: &BlobKey,
        generation: GenerationId,
        oids: &[Oid],
        anchor: Option<PackageAnchor>,
    ) -> Result<WorkspaceContentPackageFacts> {
        let result = self.store.workspace_content_package_facts_on(
            &self.connection,
            key,
            generation,
            oids,
            anchor,
        );
        self.observe(result)
    }
    pub fn index_digests<A: StoreLanguageAdapter>(
        &self,
        adapter: &A,
        state: &FileState,
        blob: &BlobKey,
        generation: GenerationId,
        path_symbol: Option<&PathSymbolRow>,
        packages: &[String],
    ) -> Result<Option<Vec<IndexEntryDigest>>> {
        let result = self.store.file_state_index_digests_on(
            &self.connection,
            adapter,
            state,
            blob,
            generation,
            path_symbol,
            packages,
        );
        self.observe(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_epoch_and_admission_share_one_frozen_read() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let old = store
            .ensure_language_epoch_value("python", "before")
            .unwrap();
        let read = store.begin_update_projection_read().unwrap();
        read.require_epoch("python", old).unwrap();
        let new = store
            .ensure_language_epoch_value("python", "after")
            .unwrap();
        assert_ne!(old, new);
        // Epoch and admission see the same SQLite snapshot even after a writer
        // commits a new epoch. No lease or second connection participates.
        read.require_epoch("python", old).unwrap();
        let key = BlobKey::unvaried(git2::Oid::zero(), "python");
        let generations = [("python".to_owned(), old)].into_iter().collect();
        assert!(
            read.parsed_blob_keys(&[key], &generations)
                .unwrap()
                .is_empty()
        );
        drop(read);
        let later = store.begin_update_projection_read().unwrap();
        assert!(later.require_epoch("python", old).is_err());
        later.require_epoch("python", new).unwrap();
    }
}
