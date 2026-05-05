//! Wire format for per-file analyzer payloads.
//!
//! `FileState` cannot be serialized directly because it embeds `CodeUnit`
//! values that each carry an `Arc<ProjectFile>`. Persisting that would
//! duplicate path strings inside every code unit, and deserializing would
//! lose the in-memory Arc sharing.
//!
//! Instead we serialize `PersistedFileState`: the same logical content with
//! `ProjectFile` stripped from each `CodeUnit`. The owning `ProjectFile` is
//! re-attached on hydrate using the row key from the storage layer.

use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{CodeUnit, CodeUnitType, ImportInfo, ProjectFile, Range};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use serde::{Deserialize, Serialize};
use std::io;

/// Bincode envelope version. Bumped when the wire format changes in a way
/// that cannot be deserialized by older readers; persisted rows tagged with
/// an unknown version are treated as dirty and re-analyzed.
pub(crate) const PAYLOAD_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct PersistedCodeUnit {
    kind: CodeUnitType,
    package_name: String,
    short_name: String,
    signature: Option<String>,
    synthetic: bool,
}

impl PersistedCodeUnit {
    fn from_code_unit(code_unit: &CodeUnit) -> Self {
        Self {
            kind: code_unit.kind(),
            package_name: code_unit.package_name().to_string(),
            short_name: code_unit.short_name().to_string(),
            signature: code_unit.signature().map(|s| s.to_string()),
            synthetic: code_unit.is_synthetic(),
        }
    }

    fn into_code_unit(self, source: &ProjectFile) -> CodeUnit {
        CodeUnit::with_signature(
            source.clone(),
            self.kind,
            self.package_name,
            self.short_name,
            self.signature,
            self.synthetic,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedFileState {
    version: u32,
    source: String,
    package_name: String,
    contains_tests: bool,
    top_level_declarations: Vec<PersistedCodeUnit>,
    declarations: Vec<PersistedCodeUnit>,
    import_statements: Vec<String>,
    imports: Vec<ImportInfo>,
    raw_supertypes: Vec<(PersistedCodeUnit, Vec<String>)>,
    type_identifiers: Vec<String>,
    signatures: Vec<(PersistedCodeUnit, Vec<String>)>,
    ranges: Vec<(PersistedCodeUnit, Vec<Range>)>,
    children: Vec<(PersistedCodeUnit, Vec<PersistedCodeUnit>)>,
    type_aliases: Vec<PersistedCodeUnit>,
}

impl PersistedFileState {
    fn from_file_state(state: &FileState) -> Self {
        Self {
            version: PAYLOAD_VERSION,
            source: state.source.clone(),
            package_name: state.package_name.clone(),
            contains_tests: state.contains_tests,
            top_level_declarations: state
                .top_level_declarations
                .iter()
                .map(PersistedCodeUnit::from_code_unit)
                .collect(),
            declarations: state
                .declarations
                .iter()
                .map(PersistedCodeUnit::from_code_unit)
                .collect(),
            import_statements: state.import_statements.clone(),
            imports: state.imports.clone(),
            raw_supertypes: state
                .raw_supertypes
                .iter()
                .map(|(unit, parents)| (PersistedCodeUnit::from_code_unit(unit), parents.clone()))
                .collect(),
            type_identifiers: state.type_identifiers.iter().cloned().collect(),
            signatures: state
                .signatures
                .iter()
                .map(|(unit, sigs)| (PersistedCodeUnit::from_code_unit(unit), sigs.clone()))
                .collect(),
            ranges: state
                .ranges
                .iter()
                .map(|(unit, ranges)| (PersistedCodeUnit::from_code_unit(unit), ranges.clone()))
                .collect(),
            children: state
                .children
                .iter()
                .map(|(parent, descendants)| {
                    (
                        PersistedCodeUnit::from_code_unit(parent),
                        descendants
                            .iter()
                            .map(PersistedCodeUnit::from_code_unit)
                            .collect(),
                    )
                })
                .collect(),
            type_aliases: state
                .type_aliases
                .iter()
                .map(PersistedCodeUnit::from_code_unit)
                .collect(),
        }
    }

    fn into_file_state(self, source: &ProjectFile) -> FileState {
        let top_level_declarations = self
            .top_level_declarations
            .into_iter()
            .map(|p| p.into_code_unit(source))
            .collect();

        let mut declarations = set_with_capacity(self.declarations.len());
        for unit in self.declarations {
            declarations.insert(unit.into_code_unit(source));
        }

        let mut raw_supertypes = map_with_capacity(self.raw_supertypes.len());
        for (unit, parents) in self.raw_supertypes {
            raw_supertypes.insert(unit.into_code_unit(source), parents);
        }

        let mut type_identifiers: HashSet<String> = set_with_capacity(self.type_identifiers.len());
        for ident in self.type_identifiers {
            type_identifiers.insert(ident);
        }

        let mut signatures = map_with_capacity(self.signatures.len());
        for (unit, sigs) in self.signatures {
            signatures.insert(unit.into_code_unit(source), sigs);
        }

        let mut ranges = map_with_capacity(self.ranges.len());
        for (unit, file_ranges) in self.ranges {
            ranges.insert(unit.into_code_unit(source), file_ranges);
        }

        let mut children: HashMap<CodeUnit, Vec<CodeUnit>> = map_with_capacity(self.children.len());
        for (parent, descendants) in self.children {
            let parent_cu = parent.into_code_unit(source);
            let descendants_cu = descendants
                .into_iter()
                .map(|p| p.into_code_unit(source))
                .collect();
            children.insert(parent_cu, descendants_cu);
        }

        let mut type_aliases = set_with_capacity(self.type_aliases.len());
        for unit in self.type_aliases {
            type_aliases.insert(unit.into_code_unit(source));
        }

        FileState {
            source: self.source,
            package_name: self.package_name,
            top_level_declarations,
            declarations,
            import_statements: self.import_statements,
            imports: self.imports,
            raw_supertypes,
            type_identifiers,
            signatures,
            ranges,
            children,
            type_aliases,
            contains_tests: self.contains_tests,
        }
    }
}

/// Serialize a `FileState` to a compact bincode blob suitable for a SQLite
/// `BLOB` column.
pub(crate) fn encode(state: &FileState) -> io::Result<Vec<u8>> {
    let dto = PersistedFileState::from_file_state(state);
    bincode::serialize(&dto).map_err(io::Error::other)
}

/// Deserialize a previously-encoded blob back into a `FileState`. The
/// `source` argument supplies the `ProjectFile` re-attached to every
/// `CodeUnit` rebuilt from the blob.
pub(crate) fn decode(bytes: &[u8], source: &ProjectFile) -> io::Result<FileState> {
    let dto: PersistedFileState = bincode::deserialize(bytes).map_err(io::Error::other)?;
    if dto.version != PAYLOAD_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unknown payload version {} (expected {})",
                dto.version, PAYLOAD_VERSION
            ),
        ));
    }
    Ok(dto.into_file_state(source))
}
