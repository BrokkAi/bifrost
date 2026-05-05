use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, ImportInfo, Language, ProjectFile, Range,
};
use crate::hash::HashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const CACHE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub(crate) struct AnalyzerDiskCache {
    path: PathBuf,
    root: PathBuf,
    language: Language,
    analysis_epoch: u64,
}

#[derive(Debug)]
pub(crate) struct CacheLoadResult {
    pub(crate) files: HashMap<ProjectFile, FileState>,
    pub(crate) dirty_files: Vec<ProjectFile>,
}

impl AnalyzerDiskCache {
    pub(crate) fn new(root: &Path, language: Language, config: &AnalyzerConfig) -> Option<Self> {
        let cache_dir = config.persistence_cache_dir(root)?;
        Some(Self {
            path: cache_dir.join(cache_file_name(language)),
            root: root.to_path_buf(),
            language,
            analysis_epoch: config.persistence.analysis_epoch,
        })
    }

    pub(crate) fn load_clean_files(&self, current_files: &[ProjectFile]) -> CacheLoadResult {
        let Some(document) = self.read_document() else {
            return CacheLoadResult {
                files: HashMap::default(),
                dirty_files: current_files.to_vec(),
            };
        };

        if document.schema_version != CACHE_SCHEMA_VERSION
            || document.language != self.language
            || document.analysis_epoch != self.analysis_epoch
        {
            return CacheLoadResult {
                files: HashMap::default(),
                dirty_files: current_files.to_vec(),
            };
        }

        let entries_by_path: BTreeMap<_, _> = document
            .files
            .into_iter()
            .map(|entry| (entry.rel_path.clone(), entry))
            .collect();
        let mut files = HashMap::default();
        let mut dirty_files = Vec::new();

        for file in current_files {
            let rel_path = path_to_cache_string(file.rel_path());
            let Some(entry) = entries_by_path.get(&rel_path) else {
                dirty_files.push(file.clone());
                continue;
            };
            let Some(current_staleness) = file_staleness(file, self.analysis_epoch) else {
                dirty_files.push(file.clone());
                continue;
            };
            if entry.staleness != current_staleness {
                dirty_files.push(file.clone());
                continue;
            }

            match entry.payload.clone().hydrate(&self.root) {
                Some(state) => {
                    files.insert(file.clone(), state);
                }
                None => dirty_files.push(file.clone()),
            }
        }

        CacheLoadResult { files, dirty_files }
    }

    pub(crate) fn save<A>(&self, files: &HashMap<ProjectFile, FileState>, adapter: &A)
    where
        A: LanguageAdapter,
    {
        let document = StoredAnalyzerCache {
            schema_version: CACHE_SCHEMA_VERSION,
            language: self.language,
            analysis_epoch: self.analysis_epoch,
            files: stored_file_entries(files, self.analysis_epoch),
            symbols: stored_symbol_rows(files, adapter),
        };

        let Some(parent) = self.path.parent() else {
            return;
        };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(encoded) = serde_json::to_string_pretty(&document) else {
            return;
        };
        let _ = fs::write(&self.path, encoded);
    }

    fn read_document(&self) -> Option<StoredAnalyzerCache> {
        let raw = fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&raw).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAnalyzerCache {
    schema_version: u32,
    language: Language,
    analysis_epoch: u64,
    files: Vec<StoredFileEntry>,
    symbols: Vec<StoredSymbolRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredFileEntry {
    rel_path: String,
    staleness: StoredFileStaleness,
    payload: StoredFileState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFileStaleness {
    size: u64,
    mtime_ns: u64,
    source_hash: u64,
    analysis_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredFileState {
    source: String,
    package_name: String,
    top_level_declarations: Vec<StoredCodeUnit>,
    declarations: Vec<StoredCodeUnit>,
    import_statements: Vec<String>,
    imports: Vec<ImportInfo>,
    raw_supertypes: Vec<(StoredCodeUnit, Vec<String>)>,
    type_identifiers: Vec<String>,
    signatures: Vec<(StoredCodeUnit, Vec<String>)>,
    ranges: Vec<(StoredCodeUnit, Vec<Range>)>,
    children: Vec<(StoredCodeUnit, Vec<StoredCodeUnit>)>,
    type_aliases: Vec<StoredCodeUnit>,
    contains_tests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct StoredCodeUnit {
    rel_path: String,
    kind: CodeUnitType,
    package_name: String,
    short_name: String,
    signature: Option<String>,
    synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSymbolRow {
    normalized_fq_name: String,
    rel_path: String,
    kind: CodeUnitType,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
}

impl StoredFileState {
    fn from_file_state(state: &FileState) -> Self {
        Self {
            source: state.source.clone(),
            package_name: state.package_name.clone(),
            top_level_declarations: stored_code_units_in_order(state.top_level_declarations.iter()),
            declarations: stored_code_units(state.declarations.iter()),
            import_statements: state.import_statements.clone(),
            imports: state.imports.clone(),
            raw_supertypes: stored_code_unit_map(&state.raw_supertypes),
            type_identifiers: sorted_strings(state.type_identifiers.iter()),
            signatures: stored_code_unit_map(&state.signatures),
            ranges: stored_code_unit_map(&state.ranges),
            children: stored_code_unit_children(&state.children),
            type_aliases: stored_code_units(state.type_aliases.iter()),
            contains_tests: state.contains_tests,
        }
    }

    fn hydrate(self, root: &Path) -> Option<FileState> {
        Some(FileState {
            source: self.source,
            package_name: self.package_name,
            top_level_declarations: hydrate_code_units(self.top_level_declarations, root),
            declarations: hydrate_code_units(self.declarations, root)
                .into_iter()
                .collect(),
            import_statements: self.import_statements,
            imports: self.imports,
            raw_supertypes: hydrate_code_unit_map(self.raw_supertypes, root),
            type_identifiers: self.type_identifiers.into_iter().collect(),
            signatures: hydrate_code_unit_map(self.signatures, root),
            ranges: hydrate_code_unit_map(self.ranges, root),
            children: hydrate_code_unit_children(self.children, root),
            type_aliases: hydrate_code_units(self.type_aliases, root)
                .into_iter()
                .collect(),
            contains_tests: self.contains_tests,
        })
    }
}

impl StoredCodeUnit {
    fn from_code_unit(code_unit: &CodeUnit) -> Self {
        Self {
            rel_path: path_to_cache_string(code_unit.source().rel_path()),
            kind: code_unit.kind(),
            package_name: code_unit.package_name().to_string(),
            short_name: code_unit.short_name().to_string(),
            signature: code_unit.signature().map(str::to_string),
            synthetic: code_unit.is_synthetic(),
        }
    }

    fn hydrate(self, root: &Path) -> CodeUnit {
        CodeUnit::with_signature(
            ProjectFile::new(root.to_path_buf(), PathBuf::from(self.rel_path)),
            self.kind,
            self.package_name,
            self.short_name,
            self.signature,
            self.synthetic,
        )
    }
}

fn stored_file_entries(
    files: &HashMap<ProjectFile, FileState>,
    analysis_epoch: u64,
) -> Vec<StoredFileEntry> {
    let mut entries = Vec::new();
    for (file, state) in files {
        let Some(staleness) = file_staleness(file, analysis_epoch) else {
            continue;
        };
        entries.push(StoredFileEntry {
            rel_path: path_to_cache_string(file.rel_path()),
            staleness,
            payload: StoredFileState::from_file_state(state),
        });
    }
    entries.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    entries
}

fn stored_symbol_rows<A>(
    files: &HashMap<ProjectFile, FileState>,
    adapter: &A,
) -> Vec<StoredSymbolRow>
where
    A: LanguageAdapter,
{
    let mut rows = Vec::new();
    for state in files.values() {
        for declaration in &state.declarations {
            let first_range = state
                .ranges
                .get(declaration)
                .and_then(|ranges| ranges.iter().min_by_key(|range| range.start_byte));
            rows.push(StoredSymbolRow {
                normalized_fq_name: adapter.normalize_full_name(&declaration.fq_name()),
                rel_path: path_to_cache_string(declaration.source().rel_path()),
                kind: declaration.kind(),
                start_byte: first_range.map(|range| range.start_byte),
                end_byte: first_range.map(|range| range.end_byte),
            });
        }
    }
    rows.sort_by(|left, right| {
        left.normalized_fq_name
            .cmp(&right.normalized_fq_name)
            .then_with(|| left.rel_path.cmp(&right.rel_path))
            .then_with(|| left.start_byte.cmp(&right.start_byte))
            .then_with(|| left.end_byte.cmp(&right.end_byte))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    rows
}

fn stored_code_units<'a>(units: impl Iterator<Item = &'a CodeUnit>) -> Vec<StoredCodeUnit> {
    let mut stored: Vec<_> = units.map(StoredCodeUnit::from_code_unit).collect();
    stored.sort();
    stored.dedup();
    stored
}

fn stored_code_units_in_order<'a>(
    units: impl Iterator<Item = &'a CodeUnit>,
) -> Vec<StoredCodeUnit> {
    units.map(StoredCodeUnit::from_code_unit).collect()
}

fn sorted_strings<'a>(values: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut values: Vec<_> = values.cloned().collect();
    values.sort();
    values.dedup();
    values
}

fn stored_code_unit_map<T: Clone>(
    map: &HashMap<CodeUnit, Vec<T>>,
) -> Vec<(StoredCodeUnit, Vec<T>)> {
    let mut stored: Vec<_> = map
        .iter()
        .map(|(unit, values)| (StoredCodeUnit::from_code_unit(unit), values.clone()))
        .collect();
    stored.sort_by(|(left, _), (right, _)| left.cmp(right));
    stored
}

fn stored_code_unit_children(
    map: &HashMap<CodeUnit, Vec<CodeUnit>>,
) -> Vec<(StoredCodeUnit, Vec<StoredCodeUnit>)> {
    let mut stored: Vec<_> = map
        .iter()
        .map(|(unit, values)| {
            (
                StoredCodeUnit::from_code_unit(unit),
                stored_code_units(values.iter()),
            )
        })
        .collect();
    stored.sort_by(|(left, _), (right, _)| left.cmp(right));
    stored
}

fn hydrate_code_units(units: Vec<StoredCodeUnit>, root: &Path) -> Vec<CodeUnit> {
    units.into_iter().map(|unit| unit.hydrate(root)).collect()
}

fn hydrate_code_unit_map<T>(
    map: Vec<(StoredCodeUnit, Vec<T>)>,
    root: &Path,
) -> HashMap<CodeUnit, Vec<T>> {
    map.into_iter()
        .map(|(unit, values)| (unit.hydrate(root), values))
        .collect()
}

fn hydrate_code_unit_children(
    map: Vec<(StoredCodeUnit, Vec<StoredCodeUnit>)>,
    root: &Path,
) -> HashMap<CodeUnit, Vec<CodeUnit>> {
    map.into_iter()
        .map(|(unit, values)| (unit.hydrate(root), hydrate_code_units(values, root)))
        .collect()
}

fn file_staleness(file: &ProjectFile, analysis_epoch: u64) -> Option<StoredFileStaleness> {
    let metadata = fs::metadata(file.abs_path()).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or_default();
    let bytes = fs::read(file.abs_path()).ok()?;

    Some(StoredFileStaleness {
        size: metadata.len(),
        mtime_ns,
        source_hash: stable_hash(&bytes),
        analysis_epoch,
    })
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn path_to_cache_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn cache_file_name(language: Language) -> String {
    format!("{:?}.json", language).to_ascii_lowercase()
}
