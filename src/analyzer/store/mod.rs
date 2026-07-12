pub mod epoch;
pub mod gc;
pub mod liveness;
pub mod query;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use git2::Oid;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};
use tree_sitter::Language as TsLanguage;

use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter};
use crate::analyzer::{
    CodeUnit, CodeUnitType, ImportInfo, Language, ProjectFile, Range, RubyMethodDispatchMode,
    SignatureMetadata, SummaryFileProjection,
};
use crate::gitblob;
use crate::hash::{HashMap, HashSet, set_with_capacity};
use crate::text_utils::compute_line_starts;

pub fn analyzer_db_path(workspace_root: &Path) -> PathBuf {
    gitblob::cache_db_path(workspace_root)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl StoreError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::new(format!("analyzer store I/O error: {err}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::new(format!("analyzer store SQLite error: {err}"))
    }
}

impl From<git2::Error> for StoreError {
    fn from(err: git2::Error) -> Self {
        Self::new(format!("analyzer store git error: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

// A completed parse is published atomically with its rows. Hot candidate
// queries rely on this marker; full count validation remains on hydration and
// explicit presence checks to quarantine externally corrupted cache rows.
const PARSED_BLOB_COMPLETE_CONDITION: &str = "meta.is_complete = 1";

const PARSED_BLOB_INTEGRITY_CONDITION: &str = "
meta.is_complete = 1
AND
meta.stored_unit_count = (
  SELECT COUNT(*) FROM code_units AS units
  WHERE units.blob_oid = meta.blob_oid AND units.lang = meta.lang
)
AND meta.range_count = (
  SELECT COUNT(*) FROM unit_ranges AS ranges
  WHERE ranges.blob_oid = meta.blob_oid AND ranges.lang = meta.lang
)
AND meta.signature_count = (
  SELECT COUNT(*) FROM unit_signatures AS signatures
  WHERE signatures.blob_oid = meta.blob_oid AND signatures.lang = meta.lang
)
AND meta.signature_metadata_count = (
  SELECT COUNT(*) FROM unit_signature_metadata AS metadata
  WHERE metadata.blob_oid = meta.blob_oid AND metadata.lang = meta.lang
)
AND meta.supertype_count = (
  SELECT COUNT(*) FROM unit_supertypes AS supertypes
  WHERE supertypes.blob_oid = meta.blob_oid AND supertypes.lang = meta.lang
)
AND meta.child_count = (
  SELECT COUNT(*) FROM unit_children AS children
  WHERE children.blob_oid = meta.blob_oid AND children.lang = meta.lang
)
AND meta.import_statement_count = (
  SELECT COUNT(*) FROM import_statements AS statements
  WHERE statements.blob_oid = meta.blob_oid AND statements.lang = meta.lang
)
AND meta.import_count = (
  SELECT COUNT(*) FROM import_details AS details
  WHERE details.blob_oid = meta.blob_oid AND details.lang = meta.lang
)
AND meta.type_identifier_count = (
  SELECT COUNT(*) FROM type_identifiers AS identifiers
  WHERE identifiers.blob_oid = meta.blob_oid AND identifiers.lang = meta.lang
)
AND meta.ruby_dispatch_count = (
  SELECT COUNT(*) FROM ruby_method_dispatch_modes AS modes
  WHERE modes.blob_oid = meta.blob_oid AND modes.lang = meta.lang
)
AND meta.scala_trait_count = (
  SELECT COUNT(*) FROM scala_traits AS traits
  WHERE traits.blob_oid = meta.blob_oid AND traits.lang = meta.lang
)";

pub struct AnalyzerStore {
    conn: Mutex<Connection>,
    db_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportFacts {
    pub(crate) package_name: String,
    pub(crate) imports: Vec<ImportInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateFlags {
    pub is_type_alias: bool,
    pub is_top_level: bool,
    pub in_declarations: bool,
    pub in_definition_lookup: bool,
    pub synthetic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow {
    pub blob_oid: Oid,
    pub lang: String,
    pub unit_key: i64,
    pub kind: CodeUnitType,
    pub short_name: String,
    pub content_qualifier: String,
    pub signature: Option<String>,
    pub flags: CandidateFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCandidateRow {
    pub candidate: CandidateRow,
    pub primary_range: Option<Range>,
    pub contains_tests: bool,
}

/// Persisted facts required to derive callable arity and return types without
/// reconstructing a complete file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFactRow {
    pub candidate: CandidateRow,
    pub signature: Option<String>,
    pub signature_metadata: Option<SignatureMetadata>,
}

impl AnalyzerStore {
    pub fn open_for_workspace(workspace_root: &Path) -> Result<Self> {
        if gitblob::discover(workspace_root).is_some() {
            Self::open_persistent(&analyzer_db_path(workspace_root))
        } else {
            Self::open_in_memory()
        }
    }

    pub fn open_persistent(db_path: &Path) -> Result<Self> {
        let conn = crate::cache_db::open_unified_connection(db_path).map_err(StoreError::new)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: Some(db_path.to_path_buf()),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        crate::cache_db::configure_connection(&mut conn).map_err(StoreError::new)?;
        crate::cache_db::migrate(&mut conn).map_err(StoreError::new)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: None,
        })
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    pub fn is_in_memory(&self) -> bool {
        self.db_path.is_none()
    }

    pub fn register_blobs(&self, oids: &[Oid], lang: &str) -> Result<()> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt =
                tx.prepare("INSERT OR IGNORE INTO blobs(blob_oid, lang) VALUES(?1, ?2)")?;
            let mut seen = HashSet::default();
            for oid in oids {
                if seen.insert(*oid) {
                    stmt.execute(params![oid.to_string(), lang])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn ensure_language_epoch(
        &self,
        language: Language,
        ts_language: &TsLanguage,
    ) -> Result<()> {
        let epoch = epoch::epoch_for(language, ts_language);
        self.ensure_language_epoch_value(language.config_label(), epoch)
    }

    pub fn ensure_language_epoch_value(&self, lang: &str, analysis_epoch: &str) -> Result<()> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        ensure_language_epoch_tx(&mut conn, lang, analysis_epoch)
    }

    pub fn missing_blobs(&self, oids: &[Oid], lang: &str) -> Result<Vec<Oid>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT 1 FROM blobs WHERE blob_oid = ?1 AND lang = ?2 LIMIT 1")?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for oid in oids {
            if !seen.insert(*oid) {
                continue;
            }
            let exists = stmt
                .query_row(params![oid.to_string(), lang], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push(*oid);
            }
        }
        Ok(out)
    }

    pub fn missing_blob_keys(&self, entries: &[(Oid, String)]) -> Result<Vec<(Oid, String)>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT 1 FROM blobs WHERE blob_oid = ?1 AND lang = ?2 LIMIT 1")?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for (oid, lang) in entries {
            if !seen.insert((*oid, lang.clone())) {
                continue;
            }
            let exists = stmt
                .query_row(params![oid.to_string(), lang], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push((*oid, lang.clone()));
            }
        }
        Ok(out)
    }

    pub fn missing_parsed_blob_keys(
        &self,
        entries: &[(Oid, String)],
    ) -> Result<Vec<(Oid, String)>> {
        let present = self.parsed_blob_keys(entries)?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for entry in entries {
            if seen.insert(entry.clone()) && !present.contains(entry) {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }

    /// Return the complete parsed keys from `entries` using chunked set queries.
    /// This reads blob metadata only; it does not hydrate file state or source.
    pub fn parsed_blob_keys(&self, entries: &[(Oid, String)]) -> Result<HashSet<(Oid, String)>> {
        const KEYS_PER_QUERY: usize = 400;

        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut unique = Vec::with_capacity(entries.len());
        let mut seen = HashSet::default();
        for entry in entries {
            if seen.insert(entry.clone()) {
                unique.push(entry.clone());
            }
        }
        let mut present = set_with_capacity(unique.len());
        for chunk in unique.chunks(KEYS_PER_QUERY) {
            if chunk.is_empty() {
                continue;
            }
            let values = std::iter::repeat_n("(?, ?)", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "WITH requested(blob_oid, lang) AS (VALUES {values})
                 SELECT requested.blob_oid, requested.lang
                 FROM requested
                 JOIN blob_meta AS meta
                   ON meta.blob_oid = requested.blob_oid
                  AND meta.lang = requested.lang
                 WHERE {PARSED_BLOB_INTEGRITY_CONDITION}"
            );
            let parameters = chunk
                .iter()
                .flat_map(|(oid, lang)| [oid.to_string(), lang.clone()])
                .collect::<Vec<_>>();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(parameters), |row| {
                let oid: String = row.get(0)?;
                let lang: String = row.get(1)?;
                Ok((oid, lang))
            })?;
            for row in rows {
                let (oid, lang) = row?;
                if let Ok(oid) = Oid::from_str(&oid) {
                    present.insert((oid, lang));
                }
            }
        }
        Ok(present)
    }

    pub fn contains_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let exists = conn
            .query_row(
                "SELECT 1 FROM blobs WHERE blob_oid = ?1 AND lang = ?2 LIMIT 1",
                params![oid.to_string(), lang],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn contains_parsed_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT 1 FROM blob_meta AS meta
             WHERE meta.blob_oid = ?1 AND meta.lang = ?2
               AND {PARSED_BLOB_INTEGRITY_CONDITION}
             LIMIT 1"
        );
        let exists = conn
            .query_row(&sql, params![oid.to_string(), lang], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn write_parsed_blob<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        state: &FileState,
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        write_parsed_blob_tx(&tx, oid, lang, adapter, state)?;
        tx.commit()?;
        Ok(())
    }

    pub fn hydrate_file_state<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<FileState>> {
        let source = file.read_to_string().unwrap_or_default();
        self.hydrate_file_state_with_source(oid, lang, adapter, file, &source)
    }

    pub fn hydrate_file_state_with_source<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Option<FileState>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        hydrate_file_state_conn(&conn, oid, lang, adapter, file, source)
    }

    /// Read only the persisted rows required to render a file summary. This
    /// does not replace full `FileState` hydration, which remains responsible
    /// for validating and serving the complete analyzer graph.
    pub fn summary_file_projection<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<SummaryFileProjection>> {
        let _scope = crate::profiling::scope("AnalyzerStore::summary_file_projection");
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        summary_file_projection_conn(&conn, oid, lang, adapter, file)
    }

    /// Hydrate many live file states from persisted blob rows using chunked
    /// `IN` scans over the requested OIDs. `source_by_file` controls whether
    /// source-dependent hydrate hooks and file-scope range synthesis run for a
    /// given file. Whole-workspace graph passes pass an empty map so they avoid
    /// all source reads and receive structural rows only.
    pub fn hydrate_file_states<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        hydrate_file_states_conn(&conn, entries, lang, adapter, source_by_file)
    }

    pub fn hydrate_file_states_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        for (lang, lang_entries) in by_lang {
            out.extend(hydrate_file_states_conn(
                &conn,
                &lang_entries,
                &lang,
                adapter,
                source_by_file,
            )?);
        }
        Ok(out)
    }

    pub fn hydrate_import_infos<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        _adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let oids = unique_oid_strings(entries);
        let imports_by_oid = read_import_infos_bulk(&conn, lang, &oids)?;
        let mut out = HashMap::default();
        for (file, oid) in entries {
            if let Some(imports) = imports_by_oid.get(&oid.to_string()) {
                out.insert(file.clone(), imports.clone());
            }
        }
        Ok(out)
    }

    pub fn hydrate_import_infos_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Ok(self
            .hydrate_import_facts_by_key(entries, adapter)?
            .into_iter()
            .map(|(file, facts)| (file, facts.imports))
            .collect())
    }

    pub(crate) fn hydrate_import_facts_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, ImportFacts>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        for (lang, lang_entries) in by_lang {
            let oids = unique_oid_strings(&lang_entries);
            let packages_by_oid = read_content_packages_bulk(&conn, &lang, &oids)?;
            let imports_by_oid = read_import_infos_bulk(&conn, &lang, &oids)?;
            for (file, oid) in lang_entries {
                let oid = oid.to_string();
                let Some(package_name) = packages_by_oid.get(&oid) else {
                    continue;
                };
                out.insert(
                    file.clone(),
                    ImportFacts {
                        package_name: adapter.hydrate_content_qualifier(package_name, &file),
                        imports: imports_by_oid.get(&oid).cloned().unwrap_or_default(),
                    },
                );
            }
        }
        Ok(out)
    }

    pub(crate) fn content_package(&self, oid: Oid, lang: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        Ok(read_content_packages_bulk(&conn, lang, &[oid.to_string()])?.remove(&oid.to_string()))
    }

    pub fn declaration_candidate_rows_by_short_name(
        &self,
        lang: &str,
        short_name: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.short_name = ?2 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        collect_candidate_rows(stmt.query_map(params![lang, short_name], candidate_row_from_row)?)
    }

    pub fn declaration_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        short_name: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.declaration_candidate_rows_by_short_name(lang, short_name)?);
        }
        Ok(out)
    }

    pub fn declaration_candidate_rows_by_identifier_for_langs(
        &self,
        langs: &[String],
        identifier: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.identifier = ?2 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut out = Vec::new();
        let mut stmt = conn.prepare_cached(&sql)?;
        for lang in langs {
            out.extend(collect_candidate_rows(
                stmt.query_map(params![lang, identifier], candidate_row_from_row)?,
            )?);
        }
        Ok(out)
    }

    pub(crate) fn declaration_candidate_rows_by_lookup_key_for_langs(
        &self,
        langs: &[String],
        column: PersistedLookupKey,
        value: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let column = match column {
            PersistedLookupKey::ExactFqn => "exact_fqn",
            PersistedLookupKey::NormalizedFqn => "normalized_fqn",
        };
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.{column} = ?2 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_candidate_rows(
                stmt.query_map(params![lang, value], candidate_row_from_row)?,
            )?);
        }
        Ok(out)
    }

    pub(crate) fn declaration_type_rows_by_package_simple_for_langs(
        &self,
        langs: &[String],
        package: &str,
        simple: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.content_qualifier = ?2
               AND units.simple_type_name = ?3 AND units.kind = 0
               AND units.in_declarations = 1 AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_candidate_rows(stmt.query_map(
                params![lang, package, simple],
                candidate_row_from_row,
            )?)?);
        }
        Ok(out)
    }

    pub(crate) fn declaration_member_rows_for_owner_for_langs(
        &self,
        langs: &[String],
        owner: &str,
        normalized: bool,
        identifier: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let owner_column = if normalized {
            "normalized_fqn"
        } else {
            "exact_fqn"
        };
        let sql = format!(
            "SELECT child.blob_oid, child.lang, child.unit_key, child.kind, child.short_name,
                    child.content_qualifier, child.signature, child.synthetic,
                    child.is_type_alias, child.top_level_ordinal, child.in_declarations,
                    child.in_definition_lookup
             FROM code_units AS owner
             JOIN unit_children AS edge
               ON edge.blob_oid = owner.blob_oid AND edge.lang = owner.lang
              AND edge.parent_key = owner.unit_key
             JOIN code_units AS child
               ON child.blob_oid = edge.blob_oid AND child.lang = edge.lang
              AND child.unit_key = edge.child_key
             JOIN blob_meta AS meta
               ON meta.blob_oid = child.blob_oid AND meta.lang = child.lang
             WHERE owner.lang = ?1 AND owner.{owner_column} = ?2
               AND owner.in_declarations = 1 AND child.identifier = ?3
               AND child.in_declarations = 1 AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY child.blob_oid, child.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_candidate_rows(stmt.query_map(
                params![lang, owner, identifier],
                candidate_row_from_row,
            )?)?);
        }
        Ok(out)
    }

    pub(crate) fn declaration_rows_by_package_for_langs(
        &self,
        langs: &[String],
        package: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.content_qualifier = ?2
               AND units.in_declarations = 1 AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_candidate_rows(
                stmt.query_map(params![lang, package], candidate_row_from_row)?,
            )?);
        }
        Ok(out)
    }

    pub fn declaration_candidate_rows_by_lang(&self, lang: &str) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        collect_candidate_rows(stmt.query_map([lang], candidate_row_from_row)?)
    }

    /// Candidate rows for a literal ASCII substring over a persistently stable
    /// fully-qualified name. Callers must retain the Rust regex filter for
    /// final semantics and use this only when their adapter guarantees that
    /// `content_qualifier` is part of the searchable FQN.
    pub fn declaration_candidate_rows_by_literal_substring(
        &self,
        lang: &str,
        substring: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?1 AND units.in_declarations = 1
               AND (
                 instr(lower(units.short_name), lower(?2)) > 0
                 OR instr(lower(units.content_qualifier), lower(?2)) > 0
               )
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        collect_candidate_rows(stmt.query_map(params![lang, substring], candidate_row_from_row)?)
    }

    pub fn declaration_candidate_rows_by_literal_substring_for_langs(
        &self,
        langs: &[String],
        substring: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.declaration_candidate_rows_by_literal_substring(lang, substring)?);
        }
        Ok(out)
    }

    /// Search candidates carry the metadata that `search_symbols` otherwise
    /// obtains by repeatedly hydrating complete file states.
    pub fn search_candidate_rows_by_lang(&self, lang: &str) -> Result<Vec<SearchCandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup, meta.contains_tests,
                    primary_range.start_byte, primary_range.end_byte,
                    primary_range.start_line, primary_range.end_line
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             LEFT JOIN unit_ranges AS primary_range
               ON primary_range.blob_oid = units.blob_oid
              AND primary_range.lang = units.lang
              AND primary_range.unit_key = units.unit_key
              AND primary_range.ordinal = 0
             WHERE units.lang = ?1 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map([lang], search_candidate_row_from_row)?;
        collect_search_candidate_rows(rows)
    }

    pub fn search_candidate_rows_by_pattern_for_langs(
        &self,
        langs: &[String],
        _pattern: &str,
    ) -> Result<Vec<SearchCandidateRow>> {
        // Regex matching is performed after language-specific FQN hydration.
        // The storage projection intentionally supplies a complete declaration
        // candidate set while avoiding per-candidate file-state hydration.
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.search_candidate_rows_by_lang(lang)?);
        }
        Ok(out)
    }

    pub fn usage_fact_rows_by_lang(&self, lang: &str) -> Result<Vec<UsageFactRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup, signature.text, metadata.metadata
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             LEFT JOIN unit_signatures AS signature
               ON signature.blob_oid = units.blob_oid
              AND signature.lang = units.lang
              AND signature.unit_key = units.unit_key
              AND signature.ordinal = 0
             LEFT JOIN unit_signature_metadata AS metadata
               ON metadata.blob_oid = units.blob_oid
              AND metadata.lang = units.lang
              AND metadata.unit_key = units.unit_key
              AND metadata.ordinal = 0
             WHERE units.lang = ?1 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        collect_usage_fact_rows(stmt.query_map([lang], usage_fact_row_from_row)?)
    }

    pub fn usage_fact_rows_for_langs(&self, langs: &[String]) -> Result<Vec<UsageFactRow>> {
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.usage_fact_rows_by_lang(lang)?);
        }
        Ok(out)
    }

    pub fn declaration_candidate_rows_for_langs(
        &self,
        langs: &[String],
    ) -> Result<Vec<CandidateRow>> {
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.declaration_candidate_rows_by_lang(lang)?);
        }
        Ok(out)
    }

    pub fn declaration_candidate_rows_with_primary_ranges_for_langs(
        &self,
        langs: &[String],
    ) -> Result<Vec<(CandidateRow, Option<Range>)>> {
        let mut out = Vec::new();
        for lang in langs {
            let rows = self.declaration_candidate_rows_by_lang(lang)?;
            let mut oids: Vec<_> = rows.iter().map(|row| row.blob_oid).collect();
            oids.sort();
            oids.dedup();
            let ranges = self.primary_ranges_by_unit_for_lang(lang, &oids)?;
            out.extend(rows.into_iter().map(|row| {
                let range = ranges.get(&(row.blob_oid, row.unit_key)).copied();
                (row, range)
            }));
        }
        Ok(out)
    }

    fn primary_ranges_by_unit_for_lang(
        &self,
        lang: &str,
        oids: &[Oid],
    ) -> Result<HashMap<(Oid, i64), Range>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut out = HashMap::default();
        for chunk in oids.chunks(900) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT blob_oid, unit_key, start_byte, end_byte, start_line, end_line
                 FROM unit_ranges
                 WHERE lang = ? AND ordinal = 0 AND blob_oid IN ({placeholders})"
            );
            let mut params = Vec::with_capacity(chunk.len() + 1);
            params.push(lang.to_string());
            params.extend(chunk.iter().map(Oid::to_string));
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
                let oid_text = row.get::<_, String>(0)?;
                let oid = Oid::from_str(&oid_text).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok((
                    (oid, row.get::<_, i64>(1)?),
                    Range {
                        start_byte: i64_to_usize(row.get::<_, i64>(2)?)
                            .map_err(rusqlite_error_from_store)?,
                        end_byte: i64_to_usize(row.get::<_, i64>(3)?)
                            .map_err(rusqlite_error_from_store)?,
                        start_line: i64_to_usize(row.get::<_, i64>(4)?)
                            .map_err(rusqlite_error_from_store)?,
                        end_line: i64_to_usize(row.get::<_, i64>(5)?)
                            .map_err(rusqlite_error_from_store)?,
                    },
                ))
            })?;
            for row in rows {
                let (key, range) = row?;
                out.insert(key, range);
            }
        }
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_oids(
        &self,
        lang: &str,
        oids: &[Oid],
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut out = Vec::new();
        for chunk in oids.chunks(900) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                        units.content_qualifier, units.signature, units.synthetic,
                        units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                        units.in_definition_lookup
                 FROM code_units AS units
                 JOIN blob_meta AS meta
                   ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
                 WHERE units.lang = ? AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
                   AND units.blob_oid IN ({placeholders})
                   AND {PARSED_BLOB_COMPLETE_CONDITION}
                 ORDER BY units.blob_oid, units.unit_key"
            );
            let mut params = Vec::with_capacity(chunk.len() + 1);
            params.push(lang.to_string());
            params.extend(chunk.iter().map(Oid::to_string));
            let mut stmt = conn.prepare_cached(&sql)?;
            out.extend(collect_candidate_rows(stmt.query_map(
                rusqlite::params_from_iter(params.iter()),
                candidate_row_from_row,
            )?)?);
        }
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_keys(
        &self,
        entries: &[(Oid, String)],
    ) -> Result<Vec<CandidateRow>> {
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut out = Vec::new();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            out.extend(self.definition_lookup_candidate_rows_by_oids(&lang, &oids)?);
        }
        Ok(out)
    }

    pub fn declaration_candidate_rows_by_pattern(
        &self,
        lang: &str,
        _pattern: &str,
    ) -> Result<Vec<CandidateRow>> {
        // Full match semantics are over recomposed, adapter-normalized FQNs,
        // so SQL intentionally supplies a declaration-row candidate set and
        // the query layer applies the existing Rust regex semantics after
        // live-path expansion.
        self.declaration_candidate_rows_by_lang(lang)
    }

    pub fn declaration_candidate_rows_by_pattern_for_langs(
        &self,
        langs: &[String],
        pattern: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut out = Vec::new();
        for lang in langs {
            out.extend(self.declaration_candidate_rows_by_pattern(lang, pattern)?);
        }
        Ok(out)
    }

    pub fn blobs_with_structured_imports(&self, lang: &str, oids: &[Oid]) -> Result<HashSet<Oid>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let mut out = HashSet::default();
        for chunk in oids.chunks(900) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT DISTINCT imports.blob_oid
                 FROM import_details AS imports
                 JOIN blob_meta AS meta
                   ON meta.blob_oid = imports.blob_oid AND meta.lang = imports.lang
                 WHERE imports.lang = ?
                   AND imports.blob_oid IN ({placeholders})
                   AND {PARSED_BLOB_COMPLETE_CONDITION}"
            );
            let mut params = Vec::with_capacity(chunk.len() + 1);
            params.push(lang.to_string());
            params.extend(chunk.iter().map(Oid::to_string));
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
                let oid_text = row.get::<_, String>(0)?;
                Oid::from_str(&oid_text).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })
            })?;
            for row in rows {
                out.insert(row?);
            }
        }
        Ok(out)
    }

    pub fn blobs_with_structured_imports_by_keys(
        &self,
        entries: &[(Oid, String)],
    ) -> Result<HashSet<(Oid, String)>> {
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut out = HashSet::default();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            for oid in self.blobs_with_structured_imports(&lang, &oids)? {
                out.insert((oid, lang.clone()));
            }
        }
        Ok(out)
    }

    pub fn content_row_count(&self, oid: Oid, lang: &str) -> Result<usize> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let oid = oid.to_string();
        let mut total = 0usize;
        for table in [
            "code_units",
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_supertypes",
            "unit_children",
            "import_statements",
            "import_details",
            "blob_meta",
            "type_identifiers",
            "ruby_method_dispatch_modes",
            "scala_traits",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = ?2");
            total += conn.query_row(&sql, params![oid, lang], |row| row.get::<_, usize>(0))?;
        }
        Ok(total)
    }

    pub fn gc_with_bloom(&self, reachable: &GrowableBloom) -> Result<usize> {
        self.gc_with(|oid| reachable.contains(oid))
    }

    pub fn gc_with(&self, keep: impl Fn(&str) -> bool) -> Result<usize> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        let dead: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT blob_oid, lang FROM blobs")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut dead = Vec::new();
            for row in rows {
                let (oid, lang) = row?;
                if !keep(&oid) {
                    dead.push((oid, lang));
                }
            }
            dead
        };
        {
            let mut del = tx.prepare("DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2")?;
            for (oid, lang) in &dead {
                del.execute(params![oid, lang])?;
            }
        }
        tx.commit()?;
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(dead.len())
    }

    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let stored: i64 = conn.query_row(
            "SELECT last_gc_at FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Some(stored)
            .filter(|at| *at > 0)
            .map(|at| crate::cache_db::now_unix_seconds() - at))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PersistedLookupKey {
    ExactFqn,
    NormalizedFqn,
}

#[derive(Debug, Clone)]
struct StoredUnit {
    key: i64,
    unit: CodeUnit,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PersistedSideTableCounts {
    range_count: usize,
    signature_count: usize,
    signature_metadata_count: usize,
    supertype_count: usize,
    child_count: usize,
    import_statement_count: usize,
    import_count: usize,
    type_identifier_count: usize,
    ruby_dispatch_count: usize,
    scala_trait_count: usize,
}

fn write_parsed_blob_tx<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    oid: Oid,
    lang: &str,
    adapter: &A,
    state: &FileState,
) -> Result<()> {
    let oid = oid.to_string();
    tx.execute(
        "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
        params![oid, lang],
    )?;
    tx.execute(
        "INSERT INTO blobs(blob_oid, lang) VALUES(?1, ?2)",
        params![oid, lang],
    )?;

    let units = collect_stored_units(adapter, state);
    let unit_keys: HashMap<CodeUnit, i64> = units
        .iter()
        .map(|unit| (unit.unit.clone(), unit.key))
        .collect();

    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, normalized_fqn, simple_type_name,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?;
        for stored in &units {
            let persist_lookup_keys = adapter.persist_content_stable_lookup_keys();
            let exact_fqn = persist_lookup_keys.then(|| stored.unit.fq_name());
            let normalized_fqn = exact_fqn
                .as_deref()
                .map(|fqn| adapter.normalize_full_name(fqn));
            let simple_type_name = (persist_lookup_keys && stored.unit.is_class())
                .then(|| adapter.simple_type_name(&stored.unit));
            stmt.execute(params![
                oid,
                lang,
                stored.key,
                code_unit_kind_to_i64(stored.unit.kind()),
                stored.unit.short_name(),
                stored.unit.identifier(),
                adapter.storage_content_qualifier(&stored.unit, &state.content_qualifier),
                exact_fqn,
                normalized_fqn,
                simple_type_name,
                stored.unit.signature(),
                bool_to_i64(stored.unit.is_synthetic()),
                bool_to_i64(stored.is_type_alias),
                stored.top_level_ordinal.map(usize_to_i64).transpose()?,
                bool_to_i64(stored.in_declarations),
                bool_to_i64(stored.in_definition_lookup),
            ])?;
        }
    }

    let range_count = insert_unit_ranges(tx, &oid, lang, &unit_keys, &state.ranges)?;
    let signature_count = insert_unit_signatures(tx, &oid, lang, &unit_keys, &state.signatures)?;
    let signature_metadata_count =
        insert_unit_signature_metadata(tx, &oid, lang, &unit_keys, &state.signature_metadata)?;
    let supertype_count =
        insert_unit_supertypes(tx, &oid, lang, &unit_keys, &state.raw_supertypes)?;
    let child_count = insert_unit_children(tx, &oid, lang, &unit_keys, &state.children)?;
    let ruby_dispatch_count = insert_ruby_method_dispatch_modes(
        tx,
        &oid,
        lang,
        &unit_keys,
        &state.ruby_method_dispatch_modes,
    )?;
    let scala_trait_count = insert_scala_traits(tx, &oid, lang, &unit_keys, &state.scala_traits)?;
    let (import_statement_count, import_count) = insert_imports(tx, &oid, lang, state)?;
    let side_counts = PersistedSideTableCounts {
        range_count,
        signature_count,
        signature_metadata_count,
        supertype_count,
        child_count,
        import_statement_count,
        import_count,
        type_identifier_count: state.type_identifiers.len(),
        ruby_dispatch_count,
        scala_trait_count,
    };
    insert_blob_meta(tx, &oid, lang, adapter, state, units.len(), side_counts)?;
    Ok(())
}

fn collect_stored_units<A: LanguageAdapter>(adapter: &A, state: &FileState) -> Vec<StoredUnit> {
    let mut candidates: HashSet<CodeUnit> = HashSet::default();
    candidates.extend(state.top_level_declarations.iter().cloned());
    candidates.extend(state.declarations.iter().cloned());
    candidates.extend(state.definition_lookup_units.iter().cloned());
    candidates.extend(state.raw_supertypes.keys().cloned());
    candidates.extend(state.signatures.keys().cloned());
    candidates.extend(state.signature_metadata.keys().cloned());
    candidates.extend(state.ranges.keys().cloned());
    candidates.extend(state.children.keys().cloned());
    candidates.extend(state.children.values().flatten().cloned());
    candidates.extend(state.type_aliases.iter().cloned());
    candidates.extend(state.ruby_method_dispatch_modes.keys().cloned());
    candidates.extend(state.scala_traits.iter().cloned());

    let top_level_ordinals: HashMap<CodeUnit, usize> = state
        .top_level_declarations
        .iter()
        .enumerate()
        .filter(|(_, unit)| adapter.should_persist_code_unit(unit))
        .map(|(ordinal, unit)| (unit.clone(), ordinal))
        .collect();

    let mut units: Vec<_> = candidates
        .into_iter()
        .filter(|unit| adapter.should_persist_code_unit(unit))
        .map(|unit| {
            let top_level_ordinal = top_level_ordinals.get(&unit).copied();
            StoredUnit {
                key: 0,
                is_type_alias: state.type_aliases.contains(&unit),
                top_level_ordinal,
                in_declarations: state.declarations.contains(&unit),
                in_definition_lookup: state.definition_lookup_units.contains(&unit),
                unit,
            }
        })
        .collect();

    units.sort_by(|left, right| {
        stored_unit_order_key(state, &left.unit).cmp(&stored_unit_order_key(state, &right.unit))
    });
    for (index, unit) in units.iter_mut().enumerate() {
        unit.key = index as i64;
    }
    units
}

fn stored_unit_order_key(
    state: &FileState,
    unit: &CodeUnit,
) -> (usize, String, String, i64, String, bool) {
    let first_range = state
        .ranges
        .get(unit)
        .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
        .unwrap_or(usize::MAX);
    (
        first_range,
        unit.short_name().to_string(),
        unit.signature().unwrap_or("").to_string(),
        code_unit_kind_to_i64(unit.kind()),
        unit.package_name().to_string(),
        unit.is_synthetic(),
    )
}

fn insert_unit_ranges(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_ranges(
           blob_oid, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    let mut count = 0;
    for (unit, entries) in ranges {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, range) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                usize_to_i64(range.start_byte)?,
                usize_to_i64(range.end_byte)?,
                usize_to_i64(range.start_line)?,
                usize_to_i64(range.end_line)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_signatures(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    signatures: &HashMap<CodeUnit, Vec<String>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_signatures(
           blob_oid, lang, unit_key, ordinal, text
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (unit, entries) in signatures {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, signature) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                signature
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_signature_metadata(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    metadata: &HashMap<CodeUnit, Vec<SignatureMetadata>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_signature_metadata(
           blob_oid, lang, unit_key, ordinal, metadata
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (unit, entries) in metadata {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, entry) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                serialize_blob(entry)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_supertypes(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    supertypes: &HashMap<CodeUnit, Vec<String>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_supertypes(
           blob_oid, lang, unit_key, ordinal, raw
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (unit, entries) in supertypes {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, raw) in entries.iter().enumerate() {
            stmt.execute(params![oid, lang, unit_key, usize_to_i64(ordinal)?, raw])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_children(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    children: &HashMap<CodeUnit, Vec<CodeUnit>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_children(
           blob_oid, lang, parent_key, child_key, ordinal
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (parent, entries) in children {
        let Some(parent_key) = unit_keys.get(parent) else {
            continue;
        };
        for (ordinal, child) in entries.iter().enumerate() {
            let Some(child_key) = unit_keys.get(child) else {
                continue;
            };
            stmt.execute(params![
                oid,
                lang,
                parent_key,
                child_key,
                usize_to_i64(ordinal)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_ruby_method_dispatch_modes(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    dispatch_modes: &HashMap<CodeUnit, RubyMethodDispatchMode>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO ruby_method_dispatch_modes(
           blob_oid, lang, unit_key, mode
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut count = 0;
    for (unit, mode) in dispatch_modes {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        stmt.execute(params![
            oid,
            lang,
            unit_key,
            ruby_dispatch_mode_to_i64(*mode)
        ])?;
        count += 1;
    }
    Ok(count)
}

fn insert_scala_traits(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    traits: &HashSet<CodeUnit>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO scala_traits(
           blob_oid, lang, unit_key
         ) VALUES(?1, ?2, ?3)",
    )?;
    let mut count = 0;
    for unit in traits {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        stmt.execute(params![oid, lang, unit_key])?;
        count += 1;
    }
    Ok(count)
}

fn insert_imports(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    state: &FileState,
) -> Result<(usize, usize)> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO import_statements(
           blob_oid, lang, ordinal, statement
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut statement_count = 0;
    for (ordinal, statement) in state.import_statements.iter().enumerate() {
        stmt.execute(params![oid, lang, usize_to_i64(ordinal)?, statement])?;
        statement_count += 1;
    }
    drop(stmt);
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO import_details(
           blob_oid, lang, ordinal, info
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut import_count = 0;
    for (ordinal, import) in state.imports.iter().enumerate() {
        stmt.execute(params![
            oid,
            lang,
            usize_to_i64(ordinal)?,
            serialize_blob(import)?,
        ])?;
        import_count += 1;
    }
    Ok((statement_count, import_count))
}

fn insert_blob_meta<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    adapter: &A,
    state: &FileState,
    stored_unit_count: usize,
    side_counts: PersistedSideTableCounts,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO blob_meta(
           blob_oid, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, import_count, type_identifier_count,
           ruby_dispatch_count, scala_trait_count, is_complete
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            oid,
            lang,
            bool_to_i64(adapter.storage_contains_tests(state)),
            adapter.storage_file_content_qualifier(&state.content_qualifier),
            usize_to_i64(stored_unit_count)?,
            usize_to_i64(side_counts.range_count)?,
            usize_to_i64(side_counts.signature_count)?,
            usize_to_i64(side_counts.signature_metadata_count)?,
            usize_to_i64(side_counts.supertype_count)?,
            usize_to_i64(side_counts.child_count)?,
            usize_to_i64(side_counts.import_statement_count)?,
            usize_to_i64(side_counts.import_count)?,
            usize_to_i64(side_counts.type_identifier_count)?,
            usize_to_i64(side_counts.ruby_dispatch_count)?,
            usize_to_i64(side_counts.scala_trait_count)?,
            1,
        ],
    )?;
    let mut type_identifiers: Vec<_> = state.type_identifiers.iter().collect();
    type_identifiers.sort();
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO type_identifiers(
           blob_oid, lang, type_identifier
         ) VALUES(?1, ?2, ?3)",
    )?;
    for identifier in type_identifiers {
        stmt.execute(params![oid, lang, identifier])?;
    }
    Ok(())
}

#[derive(Debug)]
struct UnitRow {
    key: i64,
    unit: CodeUnit,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
}

#[derive(Debug, Clone)]
struct RawUnitRow {
    key: i64,
    kind: CodeUnitType,
    short_name: String,
    content_qualifier: String,
    signature: Option<String>,
    synthetic: bool,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
}

#[derive(Debug, Clone)]
struct BlobMetaRow {
    contains_tests: bool,
    content_package: String,
    raw_content_package: String,
    type_identifiers: HashSet<String>,
    stored_unit_count: usize,
    side_counts: PersistedSideTableCounts,
}

#[derive(Debug, Clone, Copy)]
struct SummaryProjectionMeta {
    stored_unit_count: usize,
    range_count: usize,
    signature_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawSideTableCounts {
    range_count: i64,
    signature_count: i64,
    signature_metadata_count: i64,
    supertype_count: i64,
    child_count: i64,
    import_statement_count: i64,
    import_count: i64,
    type_identifier_count: i64,
    ruby_dispatch_count: i64,
    scala_trait_count: i64,
}

type BlobMetaRows = HashMap<String, BlobMetaRow>;
type SignatureMetadataRow = (i64, Vec<u8>);
type SignatureMetadataRows = HashMap<String, Vec<SignatureMetadataRow>>;
type RangeRow = (i64, i64, i64, i64, i64);
type RangeRows = HashMap<String, Vec<RangeRow>>;
type RubyDispatchRows = HashMap<String, Vec<(i64, i64)>>;
type ScalaTraitRows = HashMap<String, Vec<i64>>;

fn hydrate_file_state_conn<A: LanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<FileState>> {
    let oid = oid.to_string();
    let meta = read_blob_meta(conn, &oid, lang, adapter, file, source)?;
    let Some(meta) = meta else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    for row in rows {
        by_key.insert(row.key, row);
    }

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let mut declarations = set_with_capacity(by_key.len());
    let mut definition_lookup_units = HashSet::default();
    let mut type_aliases = HashSet::default();
    for row in by_key.values() {
        if row.in_declarations {
            declarations.insert(row.unit.clone());
        }
        if row.in_definition_lookup {
            definition_lookup_units.insert(row.unit.clone());
        }
        if row.is_type_alias {
            type_aliases.insert(row.unit.clone());
        }
    }

    let children = read_children(conn, &oid, lang, &by_key)?;
    let raw_supertypes = read_unit_string_vec(conn, &oid, lang, "unit_supertypes", "raw", &by_key)?;
    let ruby_method_dispatch_modes = read_ruby_method_dispatch_modes(conn, &oid, lang, &by_key)?;
    let scala_traits = read_scala_traits(conn, &oid, lang, &by_key)?;
    let import_statements = read_import_statements(conn, &oid, lang)?;
    let imports = read_import_infos(conn, &oid, lang)?;
    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let signature_metadata = read_signature_metadata(conn, &oid, lang, &by_key)?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;

    let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
        ranges: &ranges,
        signatures: &signatures,
        signature_metadata: &signature_metadata,
        raw_supertypes: &raw_supertypes,
        children: &children,
        import_statement_count: import_statements.len(),
        import_count: imports.len(),
        type_identifier_count: meta.type_identifiers.len(),
        ruby_dispatch_count: ruby_method_dispatch_modes.len(),
        scala_trait_count: scala_traits.len(),
    });
    if actual_counts != meta.side_counts {
        return Ok(None);
    }

    let mut state = FileState {
        source: String::new(),
        package_name: meta.content_package,
        content_qualifier: meta.raw_content_package,
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        declarations,
        definition_lookup_units,
        import_statements,
        imports,
        raw_supertypes,
        type_identifiers: meta.type_identifiers,
        signatures,
        signature_metadata,
        ranges,
        children,
        type_aliases,
        ruby_method_dispatch_modes,
        scala_traits,
        contains_tests: meta.contains_tests,
        parse_errors: None,
    };

    adapter.synthesize_hydrated_units(file, source, &mut state);
    synthesize_file_scope(file, source, &mut state);
    Ok(Some(state))
}

fn summary_file_projection_conn<A: LanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Option<SummaryFileProjection>> {
    let oid = oid.to_string();
    let Some(meta) = read_summary_projection_meta(conn, &oid, lang)? else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    for row in rows {
        by_key.insert(row.key, row);
    }

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;
    let children = read_children(conn, &oid, lang, &by_key)?;
    if count_vec_entries(&signatures) != meta.signature_count
        || count_vec_entries(&ranges) != meta.range_count
        || count_vec_entries(&children) != meta.child_count
    {
        return Ok(None);
    }

    Ok(Some(SummaryFileProjection {
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        signatures,
        ranges,
        children,
    }))
}

fn hydrate_file_states_conn<A: LanguageAdapter>(
    conn: &Connection,
    entries: &[(ProjectFile, Oid)],
    lang: &str,
    adapter: &A,
    source_by_file: &HashMap<ProjectFile, String>,
) -> Result<HashMap<ProjectFile, FileState>> {
    if entries.is_empty() {
        return Ok(HashMap::default());
    }

    let oids = unique_oid_strings(entries);
    let meta_by_oid = read_blob_meta_bulk(conn, lang, &oids)?;
    let unit_rows_by_oid = read_unit_rows_bulk(conn, lang, &oids)?;
    let children_by_oid = read_children_bulk(conn, lang, &oids)?;
    let supertypes_by_oid = read_unit_string_vec_bulk(conn, lang, "unit_supertypes", "raw", &oids)?;
    let signatures_by_oid =
        read_unit_string_vec_bulk(conn, lang, "unit_signatures", "text", &oids)?;
    let signature_metadata_by_oid = read_signature_metadata_bulk(conn, lang, &oids)?;
    let ranges_by_oid = read_ranges_bulk(conn, lang, &oids)?;
    let ruby_dispatch_by_oid = read_ruby_method_dispatch_modes_bulk(conn, lang, &oids)?;
    let scala_traits_by_oid = read_scala_traits_bulk(conn, lang, &oids)?;
    let import_statements_by_oid = read_import_statements_bulk(conn, lang, &oids)?;
    let import_infos_by_oid = read_import_infos_bulk(conn, lang, &oids)?;

    let mut out = HashMap::default();
    for (file, oid) in entries {
        let oid_text = oid.to_string();
        let Some(meta) = meta_by_oid.get(&oid_text) else {
            continue;
        };
        let source = source_by_file.get(file).map(String::as_str);
        let source_text = source.unwrap_or("");
        let raw_units = unit_rows_by_oid.get(&oid_text).cloned().unwrap_or_default();
        if raw_units.len() != meta.stored_unit_count {
            continue;
        }
        let mut by_key = HashMap::default();
        for raw in raw_units {
            let package_name = adapter.hydrate_content_qualifier(&raw.content_qualifier, file);
            let unit = CodeUnit::with_signature(
                file.clone(),
                raw.kind,
                package_name,
                raw.short_name,
                raw.signature,
                raw.synthetic,
            );
            by_key.insert(
                raw.key,
                UnitRow {
                    key: raw.key,
                    unit,
                    is_type_alias: raw.is_type_alias,
                    top_level_ordinal: raw.top_level_ordinal,
                    in_declarations: raw.in_declarations,
                    in_definition_lookup: raw.in_definition_lookup,
                },
            );
        }

        let mut top_level: Vec<_> = by_key
            .values()
            .filter_map(|row| {
                row.top_level_ordinal
                    .map(|ordinal| (ordinal, row.unit.clone()))
            })
            .collect();
        top_level.sort_by_key(|(ordinal, _)| *ordinal);

        let mut declarations = set_with_capacity(by_key.len());
        let mut definition_lookup_units = HashSet::default();
        let mut type_aliases = HashSet::default();
        for row in by_key.values() {
            if row.in_declarations {
                declarations.insert(row.unit.clone());
            }
            if row.in_definition_lookup {
                definition_lookup_units.insert(row.unit.clone());
            }
            if row.is_type_alias {
                type_aliases.insert(row.unit.clone());
            }
        }

        let ruby_method_dispatch_modes =
            ruby_dispatch_map_for_file(ruby_dispatch_by_oid.get(&oid_text), &by_key)?;
        let scala_traits = scala_traits_for_file(scala_traits_by_oid.get(&oid_text), &by_key);
        let import_statements = import_statements_by_oid
            .get(&oid_text)
            .cloned()
            .unwrap_or_default();
        let imports = import_infos_by_oid
            .get(&oid_text)
            .cloned()
            .unwrap_or_default();
        let raw_supertypes = unit_string_map_for_file(supertypes_by_oid.get(&oid_text), &by_key);
        let signatures = unit_string_map_for_file(signatures_by_oid.get(&oid_text), &by_key);
        let signature_metadata =
            signature_metadata_map_for_file(signature_metadata_by_oid.get(&oid_text), &by_key)?;
        let ranges = ranges_map_for_file(ranges_by_oid.get(&oid_text), &by_key)?;
        let children = children_map_for_file(children_by_oid.get(&oid_text), &by_key);

        let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
            ranges: &ranges,
            signatures: &signatures,
            signature_metadata: &signature_metadata,
            raw_supertypes: &raw_supertypes,
            children: &children,
            import_statement_count: import_statements.len(),
            import_count: imports.len(),
            type_identifier_count: meta.type_identifiers.len(),
            ruby_dispatch_count: ruby_method_dispatch_modes.len(),
            scala_trait_count: scala_traits.len(),
        });
        if actual_counts != meta.side_counts {
            continue;
        }

        let mut state = FileState {
            source: source.unwrap_or("").to_string(),
            package_name: adapter.hydrate_content_qualifier(&meta.content_package, file),
            content_qualifier: meta.content_package.clone(),
            top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
            declarations,
            definition_lookup_units,
            import_statements,
            imports,
            raw_supertypes,
            type_identifiers: meta.type_identifiers.clone(),
            signatures,
            signature_metadata,
            ranges,
            children,
            type_aliases,
            ruby_method_dispatch_modes,
            scala_traits,
            contains_tests: adapter.hydrate_contains_tests(meta.contains_tests, file, source_text),
            parse_errors: None,
        };

        if let Some(source) = source {
            adapter.synthesize_hydrated_units(file, source, &mut state);
            synthesize_file_scope(file, source, &mut state);
        }
        out.insert(file.clone(), state);
    }

    Ok(out)
}

fn read_blob_meta<A: LanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<BlobMetaRow>> {
    let row: Option<(i64, String, i64, RawSideTableCounts)> = conn
        .query_row(
            "SELECT contains_tests, content_package, stored_unit_count,
                    range_count, signature_count, signature_metadata_count, supertype_count,
                    child_count, import_statement_count, import_count, type_identifier_count,
                    ruby_dispatch_count, scala_trait_count
             FROM blob_meta
             WHERE blob_oid = ?1 AND lang = ?2 AND is_complete = 1",
            params![oid, lang],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    raw_side_table_counts_from_row(row, 3)?,
                ))
            },
        )
        .optional()?;
    let Some((contains_tests, content_package, stored_unit_count, raw_side_counts)) = row else {
        return Ok(None);
    };
    let type_identifiers = read_type_identifiers(conn, oid, lang)?;
    Ok(Some(BlobMetaRow {
        contains_tests: adapter.hydrate_contains_tests(contains_tests != 0, file, source),
        content_package: adapter.hydrate_content_qualifier(&content_package, file),
        raw_content_package: content_package,
        type_identifiers,
        stored_unit_count: i64_to_usize(stored_unit_count)?,
        side_counts: side_table_counts_from_raw(raw_side_counts)?,
    }))
}

fn read_summary_projection_meta(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<Option<SummaryProjectionMeta>> {
    let sql = format!(
        "SELECT stored_unit_count, range_count, signature_count, child_count
         FROM blob_meta AS meta
         WHERE meta.blob_oid = ?1 AND meta.lang = ?2
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    );
    let row: Option<(i64, i64, i64, i64)> = conn
        .query_row(&sql, params![oid, lang], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .optional()?;
    row.map(
        |(stored_unit_count, range_count, signature_count, child_count)| {
            Ok(SummaryProjectionMeta {
                stored_unit_count: i64_to_usize(stored_unit_count)?,
                range_count: i64_to_usize(range_count)?,
                signature_count: i64_to_usize(signature_count)?,
                child_count: i64_to_usize(child_count)?,
            })
        },
    )
    .transpose()
}

fn read_type_identifiers(conn: &Connection, oid: &str, lang: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT type_identifier FROM type_identifiers
         WHERE blob_oid = ?1 AND lang = ?2",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, String>(0))?;
    let mut out = HashSet::default();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

fn raw_side_table_counts_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<RawSideTableCounts> {
    Ok(RawSideTableCounts {
        range_count: row.get(offset)?,
        signature_count: row.get(offset + 1)?,
        signature_metadata_count: row.get(offset + 2)?,
        supertype_count: row.get(offset + 3)?,
        child_count: row.get(offset + 4)?,
        import_statement_count: row.get(offset + 5)?,
        import_count: row.get(offset + 6)?,
        type_identifier_count: row.get(offset + 7)?,
        ruby_dispatch_count: row.get(offset + 8)?,
        scala_trait_count: row.get(offset + 9)?,
    })
}

fn side_table_counts_from_raw(raw: RawSideTableCounts) -> Result<PersistedSideTableCounts> {
    Ok(PersistedSideTableCounts {
        range_count: i64_to_usize(raw.range_count)?,
        signature_count: i64_to_usize(raw.signature_count)?,
        signature_metadata_count: i64_to_usize(raw.signature_metadata_count)?,
        supertype_count: i64_to_usize(raw.supertype_count)?,
        child_count: i64_to_usize(raw.child_count)?,
        import_statement_count: i64_to_usize(raw.import_statement_count)?,
        import_count: i64_to_usize(raw.import_count)?,
        type_identifier_count: i64_to_usize(raw.type_identifier_count)?,
        ruby_dispatch_count: i64_to_usize(raw.ruby_dispatch_count)?,
        scala_trait_count: i64_to_usize(raw.scala_trait_count)?,
    })
}

fn unique_oid_strings(entries: &[(ProjectFile, Oid)]) -> Vec<String> {
    let mut seen = HashSet::default();
    let mut out = Vec::new();
    for (_, oid) in entries {
        let oid = oid.to_string();
        if seen.insert(oid.clone()) {
            out.push(oid);
        }
    }
    out
}

fn chunk_params(lang: &str, chunk: &[String]) -> Vec<String> {
    let mut params = Vec::with_capacity(chunk.len() + 1);
    params.push(lang.to_string());
    params.extend(chunk.iter().cloned());
    params
}

fn chunk_placeholders(chunk: &[String]) -> String {
    std::iter::repeat_n("?", chunk.len())
        .collect::<Vec<_>>()
        .join(",")
}

fn read_blob_meta_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<BlobMetaRows> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, contains_tests, content_package, stored_unit_count,
                    range_count, signature_count, signature_metadata_count, supertype_count,
                    child_count, import_statement_count, import_count, type_identifier_count,
                    ruby_dispatch_count, scala_trait_count
             FROM blob_meta
             WHERE lang = ? AND blob_oid IN ({placeholders}) AND is_complete = 1
             ORDER BY blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                raw_side_table_counts_from_row(row, 4)?,
            ))
        })?;
        for row in rows {
            let (oid, contains_tests, content_package, stored_unit_count, raw_side_counts) = row?;
            out.insert(
                oid,
                BlobMetaRow {
                    contains_tests: contains_tests != 0,
                    raw_content_package: content_package.clone(),
                    content_package,
                    type_identifiers: HashSet::default(),
                    stored_unit_count: i64_to_usize(stored_unit_count)?,
                    side_counts: side_table_counts_from_raw(raw_side_counts)?,
                },
            );
        }
    }

    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, type_identifier
             FROM type_identifiers
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, type_identifier"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, identifier) = row?;
            if let Some(meta) = out.get_mut(&oid) {
                meta.type_identifiers.insert(identifier);
            }
        }
    }
    Ok(out)
}

fn read_content_packages_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, String>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT meta.blob_oid, meta.content_package
             FROM blob_meta AS meta
             WHERE meta.lang = ? AND meta.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY meta.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, package_name) = row?;
            out.insert(oid, package_name);
        }
    }
    Ok(out)
}

fn read_unit_rows_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<RawUnitRow>>> {
    let mut out: HashMap<String, Vec<RawUnitRow>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, kind, short_name, content_qualifier, signature, synthetic,
                    is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup
             FROM code_units
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let kind_raw = row.get::<_, i64>(2)?;
            let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    Box::new(err),
                )
            })?;
            Ok((
                row.get::<_, String>(0)?,
                RawUnitRow {
                    key: row.get(1)?,
                    kind,
                    short_name: row.get(3)?,
                    content_qualifier: row.get(4)?,
                    signature: row.get(5)?,
                    synthetic: row.get::<_, i64>(6)? != 0,
                    is_type_alias: row.get::<_, i64>(7)? != 0,
                    top_level_ordinal: row
                        .get::<_, Option<i64>>(8)?
                        .and_then(|value| usize::try_from(value).ok()),
                    in_declarations: row.get::<_, i64>(9)? != 0,
                    in_definition_lookup: row.get::<_, i64>(10)? != 0,
                },
            ))
        })?;
        for row in rows {
            let (oid, raw) = row?;
            out.entry(oid).or_default().push(raw);
        }
    }
    Ok(out)
}

fn read_import_statements_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<String>>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, statement FROM import_statements
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, statement) = row?;
            out.entry(oid).or_default().push(statement);
        }
    }
    Ok(out)
}

fn read_import_infos_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<ImportInfo>>> {
    let mut out: HashMap<String, Vec<ImportInfo>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT imports.blob_oid, imports.info
             FROM import_details AS imports
             JOIN blob_meta AS meta
               ON meta.blob_oid = imports.blob_oid AND meta.lang = imports.lang
             WHERE imports.lang = ? AND imports.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY imports.blob_oid, imports.ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (oid, bytes) = row?;
            out.entry(oid).or_default().push(deserialize_blob(&bytes)?);
        }
    }
    Ok(out)
}

fn read_unit_string_vec_bulk(
    conn: &Connection,
    lang: &str,
    table: &str,
    value_column: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, String)>>> {
    let mut out: HashMap<String, Vec<(i64, String)>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, {value_column} FROM {table}
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, value) = row?;
            out.entry(oid).or_default().push((key, value));
        }
    }
    Ok(out)
}

fn read_signature_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<SignatureMetadataRows> {
    let mut out: SignatureMetadataRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, metadata FROM unit_signature_metadata
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, value) = row?;
            out.entry(oid).or_default().push((key, value));
        }
    }
    Ok(out)
}

fn read_ranges_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<RangeRows> {
    let mut out: RangeRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, start_byte, end_byte, start_line, end_line
             FROM unit_ranges
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (oid, key, start_byte, end_byte, start_line, end_line) = row?;
            out.entry(oid)
                .or_default()
                .push((key, start_byte, end_byte, start_line, end_line));
        }
    }
    Ok(out)
}

fn read_children_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, i64)>>> {
    let mut out: HashMap<String, Vec<(i64, i64)>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, parent_key, child_key FROM unit_children
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, parent_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, parent, child) = row?;
            out.entry(oid).or_default().push((parent, child));
        }
    }
    Ok(out)
}

fn read_ruby_method_dispatch_modes_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<RubyDispatchRows> {
    let mut out: RubyDispatchRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, mode FROM ruby_method_dispatch_modes
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, mode) = row?;
            out.entry(oid).or_default().push((key, mode));
        }
    }
    Ok(out)
}

fn read_scala_traits_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<ScalaTraitRows> {
    let mut out: ScalaTraitRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key FROM scala_traits
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (oid, key) = row?;
            out.entry(oid).or_default().push(key);
        }
    }
    Ok(out)
}

fn unit_string_map_for_file(
    rows: Option<&Vec<(i64, String)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<String>> {
    let mut out: HashMap<CodeUnit, Vec<String>> = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(value.clone());
        }
    }
    out
}

fn signature_metadata_map_for_file(
    rows: Option<&Vec<(i64, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<SignatureMetadata>>> {
    let mut out: HashMap<CodeUnit, Vec<SignatureMetadata>> = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(deserialize_blob(value)?);
        }
    }
    Ok(out)
}

fn ranges_map_for_file(
    rows: Option<&Vec<RangeRow>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for (key, start_byte, end_byte, start_line, end_line) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone()).or_default().push(Range {
                start_byte: i64_to_usize(*start_byte)?,
                end_byte: i64_to_usize(*end_byte)?,
                start_line: i64_to_usize(*start_line)?,
                end_line: i64_to_usize(*end_line)?,
            });
        }
    }
    Ok(out)
}

fn children_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<CodeUnit>> {
    let mut out: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for (parent_key, child_key) in rows.into_iter().flatten() {
        let (Some(parent), Some(child)) = (by_key.get(parent_key), by_key.get(child_key)) else {
            continue;
        };
        out.entry(parent.unit.clone())
            .or_default()
            .push(child.unit.clone());
    }
    out
}

fn ruby_dispatch_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut out = HashMap::default();
    for (key, raw_mode) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(*raw_mode)?);
        }
    }
    Ok(out)
}

fn scala_traits_for_file(
    rows: Option<&Vec<i64>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashSet<CodeUnit> {
    let mut out = HashSet::default();
    for key in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone());
        }
    }
    out
}

struct HydratedSideTableParts<'a> {
    ranges: &'a HashMap<CodeUnit, Vec<Range>>,
    signatures: &'a HashMap<CodeUnit, Vec<String>>,
    signature_metadata: &'a HashMap<CodeUnit, Vec<SignatureMetadata>>,
    raw_supertypes: &'a HashMap<CodeUnit, Vec<String>>,
    children: &'a HashMap<CodeUnit, Vec<CodeUnit>>,
    import_statement_count: usize,
    import_count: usize,
    type_identifier_count: usize,
    ruby_dispatch_count: usize,
    scala_trait_count: usize,
}

fn side_table_counts_from_hydrated_parts(
    parts: HydratedSideTableParts<'_>,
) -> PersistedSideTableCounts {
    PersistedSideTableCounts {
        range_count: count_vec_entries(parts.ranges),
        signature_count: count_vec_entries(parts.signatures),
        signature_metadata_count: count_vec_entries(parts.signature_metadata),
        supertype_count: count_vec_entries(parts.raw_supertypes),
        child_count: count_vec_entries(parts.children),
        import_statement_count: parts.import_statement_count,
        import_count: parts.import_count,
        type_identifier_count: parts.type_identifier_count,
        ruby_dispatch_count: parts.ruby_dispatch_count,
        scala_trait_count: parts.scala_trait_count,
    }
}

fn count_vec_entries<T>(map: &HashMap<CodeUnit, Vec<T>>) -> usize {
    map.values().map(Vec::len).sum()
}

fn candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow> {
    let oid_text = row.get::<_, String>(0)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let kind_raw = row.get::<_, i64>(3)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Integer, Box::new(err))
    })?;
    Ok(CandidateRow {
        blob_oid,
        lang: row.get(1)?,
        unit_key: row.get(2)?,
        kind,
        short_name: row.get(4)?,
        content_qualifier: row.get(5)?,
        signature: row.get(6)?,
        flags: CandidateFlags {
            synthetic: row.get::<_, i64>(7)? != 0,
            is_type_alias: row.get::<_, i64>(8)? != 0,
            is_top_level: row.get::<_, Option<i64>>(9)?.is_some(),
            in_declarations: row.get::<_, i64>(10)? != 0,
            in_definition_lookup: row.get::<_, i64>(11)? != 0,
        },
    })
}

fn usage_fact_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageFactRow> {
    let metadata = row
        .get::<_, Option<Vec<u8>>>(13)?
        .map(|bytes| deserialize_blob(&bytes).map_err(rusqlite_error_from_store))
        .transpose()?;
    Ok(UsageFactRow {
        candidate: candidate_row_from_row(row)?,
        signature: row.get(12)?,
        signature_metadata: metadata,
    })
}

fn search_candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SearchCandidateRow> {
    let candidate = candidate_row_from_row(row)?;
    let primary_range = match (
        row.get::<_, Option<i64>>(13)?,
        row.get::<_, Option<i64>>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<i64>>(16)?,
    ) {
        (Some(start_byte), Some(end_byte), Some(start_line), Some(end_line)) => Some(Range {
            start_byte: i64_to_usize(start_byte).map_err(rusqlite_error_from_store)?,
            end_byte: i64_to_usize(end_byte).map_err(rusqlite_error_from_store)?,
            start_line: i64_to_usize(start_line).map_err(rusqlite_error_from_store)?,
            end_line: i64_to_usize(end_line).map_err(rusqlite_error_from_store)?,
        }),
        _ => None,
    };
    Ok(SearchCandidateRow {
        candidate,
        primary_range,
        contains_tests: row.get::<_, i64>(12)? != 0,
    })
}

fn collect_candidate_rows<F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<CandidateRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn collect_usage_fact_rows<F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<UsageFactRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<UsageFactRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn collect_search_candidate_rows<F>(
    rows: rusqlite::MappedRows<'_, F>,
) -> Result<Vec<SearchCandidateRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<SearchCandidateRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn read_unit_rows<A: LanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Vec<UnitRow>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, kind, short_name, content_qualifier, signature, synthetic,
                is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup
         FROM code_units
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        let key = row.get::<_, i64>(0)?;
        let kind_raw = row.get::<_, i64>(1)?;
        let short_name = row.get::<_, String>(2)?;
        let content_qualifier = row.get::<_, String>(3)?;
        let signature = row.get::<_, Option<String>>(4)?;
        let synthetic = row.get::<_, i64>(5)? != 0;
        let is_type_alias = row.get::<_, i64>(6)? != 0;
        let top_level_ordinal = row
            .get::<_, Option<i64>>(7)?
            .and_then(|value| usize::try_from(value).ok());
        let in_declarations = row.get::<_, i64>(8)? != 0;
        let in_definition_lookup = row.get::<_, i64>(9)? != 0;
        Ok((
            key,
            kind_raw,
            short_name,
            content_qualifier,
            signature,
            synthetic,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (
            key,
            kind_raw,
            short_name,
            content_qualifier,
            signature,
            synthetic,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
        ) = row?;
        let kind = code_unit_kind_from_i64(kind_raw)?;
        let package_name = adapter.hydrate_content_qualifier(&content_qualifier, file);
        let unit = CodeUnit::with_signature(
            file.clone(),
            kind,
            package_name,
            short_name,
            signature,
            synthetic,
        );
        out.push(UnitRow {
            key,
            unit,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
        });
    }
    Ok(out)
}

fn read_import_statements(conn: &Connection, oid: &str, lang: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT statement FROM import_statements
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY ordinal",
    )?;
    collect_string_rows(stmt.query_map(params![oid, lang], |row| row.get(0))?)
}

fn read_import_infos(conn: &Connection, oid: &str, lang: &str) -> Result<Vec<ImportInfo>> {
    let mut stmt = conn.prepare(
        "SELECT info FROM import_details
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(deserialize_blob(&row?)?);
    }
    Ok(out)
}

fn read_unit_string_vec(
    conn: &Connection,
    oid: &str,
    lang: &str,
    table: &str,
    value_column: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<String>>> {
    let sql = format!(
        "SELECT unit_key, {value_column} FROM {table}
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out: HashMap<CodeUnit, Vec<String>> = HashMap::default();
    for row in rows {
        let (key, value) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone()).or_default().push(value);
        }
    }
    Ok(out)
}

fn read_signature_metadata(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<SignatureMetadata>>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, metadata FROM unit_signature_metadata
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out: HashMap<CodeUnit, Vec<SignatureMetadata>> = HashMap::default();
    for row in rows {
        let (key, metadata) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(deserialize_blob(&metadata)?);
        }
    }
    Ok(out)
}

fn read_ranges(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, start_byte, end_byte, start_line, end_line
         FROM unit_ranges
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for row in rows {
        let (key, start_byte, end_byte, start_line, end_line) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone()).or_default().push(Range {
                start_byte: i64_to_usize(start_byte)?,
                end_byte: i64_to_usize(end_byte)?,
                start_line: i64_to_usize(start_line)?,
                end_line: i64_to_usize(end_line)?,
            });
        }
    }
    Ok(out)
}

fn read_children(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<CodeUnit>>> {
    let mut stmt = conn.prepare(
        "SELECT parent_key, child_key FROM unit_children
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY parent_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for row in rows {
        let (parent_key, child_key) = row?;
        let (Some(parent), Some(child)) = (by_key.get(&parent_key), by_key.get(&child_key)) else {
            continue;
        };
        out.entry(parent.unit.clone())
            .or_default()
            .push(child.unit.clone());
    }
    Ok(out)
}

fn read_ruby_method_dispatch_modes(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, mode FROM ruby_method_dispatch_modes
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out = HashMap::default();
    for row in rows {
        let (key, raw_mode) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(raw_mode)?);
        }
    }
    Ok(out)
}

fn read_scala_traits(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashSet<CodeUnit>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key FROM scala_traits
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, i64>(0))?;
    let mut out = HashSet::default();
    for row in rows {
        let key = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone());
        }
    }
    Ok(out)
}

fn synthesize_file_scope(file: &ProjectFile, source: &str, state: &mut FileState) {
    let code_unit = CodeUnit::file_scope(file.clone());
    if state.declarations.contains(&code_unit) {
        return;
    }
    state.top_level_declarations.push(code_unit.clone());
    state.declarations.insert(code_unit.clone());
    state.ranges.entry(code_unit).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: compute_line_starts(source).len().saturating_sub(1),
    });
}

fn collect_string_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<String>>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn ensure_language_epoch_tx(conn: &mut Connection, lang: &str, analysis_epoch: &str) -> Result<()> {
    let stored_epoch: Option<String> = conn
        .query_row(
            "SELECT epoch FROM analysis_epochs WHERE lang = ?1",
            [lang],
            |row| row.get(0),
        )
        .optional()?;
    if stored_epoch.as_deref() == Some(analysis_epoch) {
        return Ok(());
    }

    let tx = conn.transaction()?;
    tx.execute("DELETE FROM blobs WHERE lang = ?1", [lang])?;
    tx.execute(
        "INSERT INTO analysis_epochs(lang, epoch) VALUES(?1, ?2)
         ON CONFLICT(lang) DO UPDATE SET epoch = excluded.epoch",
        params![lang, analysis_epoch],
    )?;
    tx.commit()?;
    Ok(())
}

fn serialize_blob<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value)
        .map_err(|err| StoreError::new(format!("analyzer store serialization error: {err}")))
}

fn deserialize_blob<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|err| StoreError::new(format!("analyzer store deserialization error: {err}")))
}

fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

fn usize_to_i64(value: usize) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| StoreError::new(format!("value does not fit in SQLite INTEGER: {value}")))
}

fn i64_to_usize(value: i64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| StoreError::new(format!("negative or too-large SQLite INTEGER: {value}")))
}

fn rusqlite_error_from_store(err: StoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

fn code_unit_kind_to_i64(kind: CodeUnitType) -> i64 {
    match kind {
        CodeUnitType::Class => 0,
        CodeUnitType::Function => 1,
        CodeUnitType::Field => 2,
        CodeUnitType::Module => 3,
        CodeUnitType::Macro => 4,
        CodeUnitType::FileScope => 5,
    }
}

fn code_unit_kind_from_i64(value: i64) -> Result<CodeUnitType> {
    match value {
        0 => Ok(CodeUnitType::Class),
        1 => Ok(CodeUnitType::Function),
        2 => Ok(CodeUnitType::Field),
        3 => Ok(CodeUnitType::Module),
        4 => Ok(CodeUnitType::Macro),
        5 => Ok(CodeUnitType::FileScope),
        _ => Err(StoreError::new(format!("invalid code unit kind: {value}"))),
    }
}

fn ruby_dispatch_mode_to_i64(mode: RubyMethodDispatchMode) -> i64 {
    match mode {
        RubyMethodDispatchMode::Instance => 0,
        RubyMethodDispatchMode::Singleton => 1,
        RubyMethodDispatchMode::ModuleFunction => 2,
    }
}

fn ruby_dispatch_mode_from_i64(value: i64) -> Result<RubyMethodDispatchMode> {
    match value {
        0 => Ok(RubyMethodDispatchMode::Instance),
        1 => Ok(RubyMethodDispatchMode::Singleton),
        2 => Ok(RubyMethodDispatchMode::ModuleFunction),
        other => Err(StoreError::new(format!(
            "unknown persisted Ruby dispatch mode {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::python::PythonAdapter;
    use crate::analyzer::ruby::RubyAdapter;
    use crate::analyzer::scala::ScalaAdapter;
    use crate::analyzer::tree_sitter_analyzer::ParsedFile;
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::gitblob::tests::{commit_all, init_repo};
    use git2::ObjectType;
    use tree_sitter::Parser;

    #[test]
    fn non_git_root_uses_in_memory_store_and_roundtrips_registry() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = AnalyzerStore::open_for_workspace(temp.path()).unwrap();
        assert!(store.is_in_memory());
        assert!(store.db_path().is_none());

        let one = Oid::hash_object(ObjectType::Blob, b"one").unwrap();
        let two = Oid::hash_object(ObjectType::Blob, b"two").unwrap();
        assert_eq!(
            store.missing_blobs(&[one, two], "rust").unwrap(),
            vec![one, two]
        );

        store.register_blobs(&[one], "rust").unwrap();
        store.register_blobs(&[one], "rust").unwrap();
        assert_eq!(store.missing_blobs(&[one, two], "rust").unwrap(), vec![two]);
        assert_eq!(store.missing_blobs(&[one], "python").unwrap(), vec![one]);
    }

    #[test]
    fn parsed_blob_presence_requires_completed_parse_rows() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"class Registered:\n    pass\n").unwrap();

        store.register_blobs(&[oid], "python").unwrap();

        assert!(store.contains_blob(oid, "python").unwrap());
        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            vec![(oid, "python".to_string())]
        );
    }

    #[test]
    fn parsed_blob_keys_batches_mixed_languages_and_incomplete_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(root, "pkg/model.py", "class Model:\n    pass\n");
        let java_file = write_file(root, "src/Model.java", "class Model {}\n");
        let python_oid = oid_for(python_file.read_to_string().unwrap().as_bytes());
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let incomplete_oid = oid_for(b"registered but not parsed");
        let missing_oid = oid_for(b"not registered");
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(
                python_oid,
                "python",
                &PythonAdapter,
                &parse_state(&PythonAdapter, &python_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                java_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store.register_blobs(&[incomplete_oid], "rust").unwrap();

        let mut entries = vec![
            (python_oid, "python".to_string()),
            (python_oid, "java".to_string()),
            (java_oid, "java".to_string()),
            (incomplete_oid, "rust".to_string()),
            (missing_oid, "python".to_string()),
            (python_oid, "python".to_string()),
        ];
        let bulk_missing = (0..405)
            .map(|index| oid_for(format!("bulk missing {index}").as_bytes()))
            .collect::<Vec<_>>();
        entries.extend(bulk_missing.iter().map(|oid| (*oid, "python".to_string())));
        assert_eq!(
            store.parsed_blob_keys(&entries).unwrap(),
            [
                (python_oid, "python".to_string()),
                (java_oid, "java".to_string()),
            ]
            .into_iter()
            .collect::<HashSet<_>>()
        );
        let missing = store.missing_parsed_blob_keys(&entries).unwrap();
        assert_eq!(missing.len(), 408);
        assert!(missing.contains(&(python_oid, "java".to_string())));
        assert!(missing.contains(&(incomplete_oid, "rust".to_string())));
        assert!(missing.contains(&(missing_oid, "python".to_string())));
        assert!(
            bulk_missing
                .iter()
                .all(|oid| missing.contains(&(*oid, "python".to_string())))
        );
    }

    #[test]
    fn summary_projection_matches_required_file_state_rows_and_rejects_missing_ranges() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Example.java",
            "package demo; class Example { String name; void run() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let projection = store
            .summary_file_projection(oid, "java", &adapter, &file)
            .unwrap()
            .expect("complete summary projection");
        let hydrated = store
            .hydrate_file_state(oid, "java", &adapter, &file)
            .unwrap()
            .expect("complete file state");
        let hydrated_top_level: Vec<_> = hydrated
            .top_level_declarations
            .into_iter()
            .filter(|unit| !unit.is_file_scope())
            .collect();
        assert_eq!(projection.top_level_declarations, hydrated_top_level);
        for (unit, signatures) in &projection.signatures {
            assert_eq!(hydrated.signatures.get(unit), Some(signatures));
        }
        for (unit, ranges) in &projection.ranges {
            assert_eq!(hydrated.ranges.get(unit), Some(ranges));
        }
        for (unit, children) in &projection.children {
            assert_eq!(hydrated.children.get(unit), Some(children));
        }

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM unit_ranges WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
            )
            .unwrap();
        }
        assert!(
            store
                .summary_file_projection(oid, "java", &adapter, &file)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bulk_import_facts_include_complete_files_without_import_details() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/NoImports.java",
            "package demo; class NoImports {}\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let facts = store
            .hydrate_import_facts_by_key(&[(file.clone(), oid, "java".to_string())], &adapter)
            .unwrap();
        let facts = facts.get(&file).expect("complete persisted import facts");
        assert_eq!(facts.package_name, "demo");
        assert!(facts.imports.is_empty());
    }

    #[test]
    fn literal_substring_candidates_keep_members_of_matching_java_types() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Gson.java",
            "package demo; class Gson { void fromJson() {} } class Other { void unrelated() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let candidates = store
            .declaration_candidate_rows_by_literal_substring("java", "Gson")
            .unwrap();
        assert!(
            candidates
                .iter()
                .any(|row| row.short_name.ends_with(".fromJson")),
            "Java persists member selectors with their owning type in short_name"
        );
        assert!(candidates.iter().all(|row| {
            row.short_name.to_ascii_lowercase().contains("gson")
                || row.content_qualifier.to_ascii_lowercase().contains("gson")
        }));
        assert!(
            !candidates
                .iter()
                .any(|row| row.short_name.contains("unrelated"))
        );

        let search_candidates = store.search_candidate_rows_by_lang("java").unwrap();
        let method = search_candidates
            .iter()
            .find(|row| row.candidate.short_name.ends_with(".fromJson"))
            .expect("method search candidate");
        assert!(method.primary_range.is_some());
        assert!(!method.contains_tests);
    }

    #[test]
    fn metadata_unit_count_mismatch_is_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/corrupt.py", "class Corrupt:\n    pass\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM code_units WHERE blob_oid = ?1 AND lang = 'python'",
                [oid.to_string()],
            )
            .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert!(
            store
                .hydrate_file_state(oid, "python", &adapter, &file)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn metadata_side_table_count_mismatches_are_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "require 'json'\nclass Demo\n  attr_reader :name\n  alias_method :label, :name\n  def initialize(name)\n    @name = name\n  end\n  def self.build(value)\n    new(value)\n  end\nend\n",
        );
        let python_file = write_file(
            root,
            "pkg/corrupt.py",
            "import os\nfrom sys import path\nclass Corrupt:\n    def run(self):\n        return os.getcwd()\n",
        );
        let java_file = write_file(
            root,
            "src/demo/Corrupt.java",
            "package demo;\nimport java.util.List;\nclass Corrupt extends Base { List<String> names; void run(List<String> input) {} }\nclass Base {}\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Corrupt.scala",
            "package app\ntrait Runnable\nclass Worker extends Runnable\n",
        );

        for table in [
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_children",
            "ruby_method_dispatch_modes",
        ] {
            assert_deleting_side_table_marks_incomplete(&RubyAdapter, "ruby", &ruby_file, table);
        }
        for table in ["import_statements", "import_details"] {
            assert_deleting_side_table_marks_incomplete(
                &PythonAdapter,
                "python",
                &python_file,
                table,
            );
        }
        for table in ["unit_supertypes", "type_identifiers"] {
            assert_deleting_side_table_marks_incomplete(&JavaAdapter, "java", &java_file, table);
        }
        assert_deleting_side_table_marks_incomplete(
            &ScalaAdapter,
            "scala",
            &scala_file,
            "scala_traits",
        );
    }

    #[test]
    fn parsed_blob_presence_allows_zero_persisted_units() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/side_effect_only.py", "import os\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        assert!(store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            Vec::<(Oid, String)>::new()
        );
        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state, &hydrated);
    }

    #[test]
    fn gc_drops_unreachable_blob_registry_rows() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let reachable = Oid::hash_object(ObjectType::Blob, b"reachable").unwrap();
        let unreachable = Oid::hash_object(ObjectType::Blob, b"unreachable").unwrap();
        store
            .register_blobs(&[reachable, unreachable], "rust")
            .unwrap();

        let mut bloom = GrowableBloom::new(0.01, 8);
        bloom.insert(reachable.to_string());
        assert_eq!(store.gc_with_bloom(&bloom).unwrap(), 1);
        assert_eq!(
            store
                .missing_blobs(&[reachable, unreachable], "rust")
                .unwrap(),
            vec![unreachable]
        );
    }

    #[test]
    fn language_epoch_mismatch_deletes_only_that_language() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(root, "src/demo/One.java", "package demo;\nclass One {}\n");
        let ts_file = write_file(root, "src/two.ts", "export class Two {}\n");
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let ts_oid = oid_for(ts_file.read_to_string().unwrap().as_bytes());
        let java = JavaAdapter;
        let ts = TypescriptAdapter;
        let java_state = parse_state(&java, &java_file);
        let ts_state = parse_state(&ts, &ts_file);

        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        store
            .ensure_language_epoch_value("typescript", "epoch-a")
            .unwrap();
        store
            .write_parsed_blob(java_oid, "java", &java, &java_state)
            .unwrap();
        store
            .write_parsed_blob(ts_oid, "typescript", &ts, &ts_state)
            .unwrap();

        store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        assert_eq!(
            store.missing_blobs(&[java_oid], "java").unwrap(),
            vec![java_oid]
        );
        assert_eq!(
            store.missing_blobs(&[ts_oid], "typescript").unwrap(),
            vec![]
        );
        assert_eq!(store.content_row_count(java_oid, "java").unwrap(), 0);
        assert!(store.content_row_count(ts_oid, "typescript").unwrap() > 0);
    }

    #[test]
    fn linked_worktrees_share_analyzer_db_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo = init_repo(&repo_root);
        std::fs::write(repo_root.join("tracked.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let linked_root = temp.path().join("linked");
        let worktree = repo.worktree("linked", &linked_root, None).unwrap();
        let linked_repo = git2::Repository::open_from_worktree(&worktree).unwrap();
        assert!(linked_repo.is_worktree());

        assert_eq!(
            std::fs::canonicalize(
                analyzer_db_path(&repo_root)
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
            )
            .unwrap(),
            std::fs::canonicalize(
                analyzer_db_path(&linked_root)
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            analyzer_db_path(&repo_root)
                .file_name()
                .and_then(|n| n.to_str()),
            Some(crate::cache_db::CACHE_DB_FILE_NAME)
        );
        assert_eq!(analyzer_db_path(&repo_root), analyzer_db_path(&linked_root));
    }

    #[test]
    fn round_trips_java_python_and_typescript_file_states() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(
            root,
            "src/demo/Example.java",
            "package demo;\nimport java.util.List;\nclass Example { void run() {} }\n",
        );
        let python_init = write_file(root, "pkg/__init__.py", "");
        let python_file = write_file(
            root,
            "pkg/mod.py",
            "import os\nclass Example:\n    def run(self):\n        return os.getcwd()\n",
        );
        let ts_file = write_file(
            root,
            "src/example.test.ts",
            "import {Thing} from './thing';\nexport class Example { run(): Thing { return new Thing(); } }\n",
        );
        let _ = python_init;

        assert_round_trip(&JavaAdapter, "java", &java_file);
        assert_round_trip(&PythonAdapter, "python", &python_file);
        assert_round_trip(&TypescriptAdapter, "typescript", &ts_file);
    }

    #[test]
    fn round_trips_python_crlf_class_signature() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(
            root,
            "pkg/documented.py",
            "# Comment before class\r\nclass DocumentedClass:\r\n    pass\r\n",
        );
        let source = python_file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let parsed = parse_state(&adapter, &python_file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &parsed)
            .unwrap();

        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &python_file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&parsed, &hydrated);
        assert!(
            hydrated
                .signatures
                .values()
                .flatten()
                .any(|signature| signature == "class DocumentedClass:"),
            "expected CRLF class signature to survive store round trip, got {:?}",
            hydrated.signatures
        );
    }

    #[test]
    fn round_trips_ruby_dispatch_and_scala_trait_side_tables() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "module Demo\n  module_function\n  def build(value)\n    Product.new(value)\n  end\n  class Product\n    attr_reader :name\n    alias_method :label, :name\n    def initialize(name)\n      @name = name\n    end\n    def self.featured\n      new('sample')\n    end\n  end\nend\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Demo.scala",
            "package app\ntrait Runnable\nclass Worker extends Runnable\n",
        );

        assert_round_trip(&RubyAdapter, "ruby", &ruby_file);
        assert_round_trip(&ScalaAdapter, "scala", &scala_file);
    }

    #[test]
    fn identical_python_blob_hydrates_with_live_path_names() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "class Shared:\n    def run(self):\n        return 1\n";
        let _ = write_file(root, "pkg_a/__init__.py", "");
        let _ = write_file(root, "pkg_b/__init__.py", "");
        let _ = write_file(root, "pkg_b/sub/__init__.py", "");
        let file_a = write_file(root, "pkg_a/mod.py", content);
        let file_b = write_file(root, "pkg_b/sub/mod.py", content);
        let oid = oid_for(content.as_bytes());
        let adapter = PythonAdapter;
        let state_a = parse_state(&adapter, &file_a);
        let state_b = parse_state(&adapter, &file_b);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state_a)
            .unwrap();
        let first_count = store.content_row_count(oid, "python").unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state_b)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "python").unwrap(), first_count);

        let hydrated_a = store
            .hydrate_file_state(oid, "python", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "python", &adapter, &file_b)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state_a, &hydrated_a);
        assert_file_state_equivalent(&state_b, &hydrated_b);
        assert_eq!(hydrated_a.package_name, "pkg_a.mod");
        assert_eq!(hydrated_b.package_name, "pkg_b.sub.mod");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_a.mod.Shared")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_b.sub.mod.Shared")
        );
    }

    #[test]
    fn identical_go_blob_hydrates_with_live_import_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let _ = write_file(root, "go.mod", "module example.com/demo\n");
        let content = "package service\ntype Client struct{}\n";
        let file_a = write_file(root, "alpha/client.go", content);
        let file_b = write_file(root, "beta/client.go", content);
        let oid = oid_for(content.as_bytes());
        let adapter = GoAdapter;
        let state = parse_state(&adapter, &file_a);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "go", &adapter, &state)
            .unwrap();
        let hydrated_a = store
            .hydrate_file_state(oid, "go", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "go", &adapter, &file_b)
            .unwrap()
            .unwrap();

        assert_eq!(hydrated_a.content_qualifier, "service");
        assert_eq!(hydrated_b.content_qualifier, "service");
        assert_eq!(hydrated_a.package_name, "example.com/demo/alpha");
        assert_eq!(hydrated_b.package_name, "example.com/demo/beta");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/alpha.Client")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/beta.Client")
        );
    }

    #[test]
    fn writer_is_idempotent_for_same_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/demo/Repeat.java",
            "package demo;\nclass Repeat { int value; }\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        let first_count = store.content_row_count(oid, "java").unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "java").unwrap(), first_count);
    }

    #[test]
    fn rejects_bad_blob_oid_hex() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, ?2)",
                params!["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "rust"],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_inverted_unit_range() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_ranges(
                   blob_oid, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
                 ) VALUES(?1, 'rust', 1, 0, 10, 2, 4, 3)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_self_parent_child_edge() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_children(blob_oid, lang, parent_key, child_key, ordinal)
                 VALUES(?1, 'rust', 1, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_satellite_row_without_code_unit_parent() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let err = conn
            .execute(
                "INSERT INTO unit_signatures(blob_oid, lang, unit_key, ordinal, text)
                 VALUES(?1, 'rust', 99, 0, 'fn orphan()')",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "FOREIGN KEY");
    }

    #[test]
    fn rejects_forbidden_persisted_code_unit_kinds() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let file_scope_err = conn
            .execute(
                "INSERT INTO code_units(
                   blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
                   signature, synthetic, is_type_alias, top_level_ordinal,
                   in_declarations, in_definition_lookup
                 ) VALUES(?1, 'rust', 1, 5, 'file', 'file', '', NULL, 0, 0, 0, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(file_scope_err, "CHECK");

        let python_module_err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'python')",
                [TEST_OID],
            )
            .and_then(|_| {
                conn.execute(
                    "INSERT INTO code_units(
                       blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
                       signature, synthetic, is_type_alias, top_level_ordinal,
                       in_declarations, in_definition_lookup
                     ) VALUES(?1, 'python', 1, 3, 'mod', 'mod', '', NULL, 0, 0, 0, 1, 0)",
                    [TEST_OID],
                )
            })
            .unwrap_err();
        assert_constraint_error(python_module_err, "CHECK");
    }

    fn assert_round_trip<A: LanguageAdapter>(adapter: &A, lang: &str, file: &ProjectFile) {
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let parsed = parse_state(adapter, file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, lang, adapter, &parsed)
            .unwrap();
        let hydrated = store
            .hydrate_file_state(oid, lang, adapter, file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&parsed, &hydrated);
        assert!(hydrated.source.is_empty());
        assert!(hydrated.parse_errors.is_none());
    }

    fn assert_deleting_side_table_marks_incomplete<A: LanguageAdapter>(
        adapter: &A,
        lang: &str,
        file: &ProjectFile,
        table: &str,
    ) {
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let parsed = parse_state(adapter, file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, lang, adapter, &parsed)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            let count_sql =
                format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = ?2");
            let count: usize = conn
                .query_row(&count_sql, params![oid.to_string(), lang], |row| row.get(0))
                .unwrap();
            assert!(
                count > 0,
                "fixture should persist at least one {table} row for {lang}"
            );
            let delete_sql = format!("DELETE FROM {table} WHERE blob_oid = ?1 AND lang = ?2");
            conn.execute(&delete_sql, params![oid.to_string(), lang])
                .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, lang).unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, lang.to_string())])
                .unwrap(),
            vec![(oid, lang.to_string())]
        );
        assert!(
            store
                .hydrate_file_state(oid, lang, adapter, file)
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .hydrate_file_states(&[(file.clone(), oid)], lang, adapter, &HashMap::default())
                .unwrap()
                .contains_key(file)
        );
    }

    fn parse_state<A: LanguageAdapter>(adapter: &A, file: &ProjectFile) -> FileState {
        let source = file.read_to_string().unwrap();
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language())
            .expect("set parser language");
        let tree = parser.parse(source.as_str(), None).expect("parse file");
        let mut parsed: ParsedFile = adapter.parse_file(file, &source, &tree);
        parsed.add_file_scope(file, &source);
        let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);
        FileState {
            source,
            content_qualifier: parsed.content_qualifier,
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations: parsed.declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            import_statements: parsed.import_statements,
            imports: parsed.imports,
            raw_supertypes: parsed.raw_supertypes,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            ranges: parsed.ranges,
            children: parsed.children,
            type_aliases: parsed.type_aliases,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            scala_traits: parsed.scala_traits,
            contains_tests,
            parse_errors: Some(Vec::new()),
        }
    }

    fn assert_file_state_equivalent(expected: &FileState, actual: &FileState) {
        assert_eq!(actual.package_name, expected.package_name);
        assert_eq!(
            actual.top_level_declarations,
            expected.top_level_declarations
        );
        assert_eq!(actual.declarations, expected.declarations);
        assert_eq!(
            actual.definition_lookup_units,
            expected.definition_lookup_units
        );
        assert_eq!(actual.import_statements, expected.import_statements);
        assert_eq!(actual.imports, expected.imports);
        assert_eq!(
            non_empty_string_vec_entries(&actual.raw_supertypes),
            non_empty_string_vec_entries(&expected.raw_supertypes)
        );
        assert_eq!(actual.type_identifiers, expected.type_identifiers);
        assert_eq!(actual.signatures, expected.signatures);
        assert_eq!(actual.signature_metadata, expected.signature_metadata);
        assert_eq!(actual.ranges, expected.ranges);
        assert_eq!(
            non_empty_code_unit_vec_entries(&actual.children),
            non_empty_code_unit_vec_entries(&expected.children)
        );
        assert_eq!(actual.type_aliases, expected.type_aliases);
        assert_eq!(
            actual.ruby_method_dispatch_modes,
            expected.ruby_method_dispatch_modes
        );
        assert_eq!(actual.scala_traits, expected.scala_traits);
        assert_eq!(actual.contains_tests, expected.contains_tests);
        assert!(actual.source.is_empty());
        assert!(actual.parse_errors.is_none());
    }

    fn non_empty_string_vec_entries(
        map: &HashMap<CodeUnit, Vec<String>>,
    ) -> HashMap<CodeUnit, Vec<String>> {
        map.iter()
            .filter(|(_, values)| !values.is_empty())
            .map(|(unit, values)| (unit.clone(), values.clone()))
            .collect()
    }

    fn non_empty_code_unit_vec_entries(
        map: &HashMap<CodeUnit, Vec<CodeUnit>>,
    ) -> HashMap<CodeUnit, Vec<CodeUnit>> {
        map.iter()
            .filter(|(_, values)| !values.is_empty())
            .map(|(unit, values)| (unit.clone(), values.clone()))
            .collect()
    }

    const TEST_OID: &str = "1111111111111111111111111111111111111111";

    fn insert_test_blob_and_unit(conn: &Connection) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', 1, 0, 'Thing', 'Thing', '', NULL, 0, 0, 0, 1, 0)",
            [TEST_OID],
        )
        .unwrap();
    }

    fn assert_constraint_error(err: rusqlite::Error, expected: &str) {
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "expected {expected} constraint error, got {message}"
        );
    }

    fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel_path);
        file.write(contents).unwrap();
        file
    }

    fn oid_for(contents: &[u8]) -> Oid {
        Oid::hash_object(ObjectType::Blob, contents).unwrap()
    }
}
