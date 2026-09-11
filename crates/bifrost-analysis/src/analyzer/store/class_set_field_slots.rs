//! Normalized persistence for complete, exact-workspace class-set field slots.

use std::path::Path;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::{AnalyzerStore, Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::semantic::{
    SemanticWork, SourcePosition, SourceSpan, StableDigest, WorkspaceRelativePath,
};

pub type ClassSetFieldSlotDigest = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassSetFieldSlotIndexKey {
    pub language: Language,
    pub workspace_content_digest: ClassSetFieldSlotDigest,
    pub provider_behavior_digest: ClassSetFieldSlotDigest,
    pub active_pack_digest: ClassSetFieldSlotDigest,
    pub adapter_semantics_digest: ClassSetFieldSlotDigest,
    pub representation_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldSlotArtifactRow {
    pub rel_path: String,
    pub public_digest: ClassSetFieldSlotDigest,
    pub work: SemanticWork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetFieldSlotClassRow {
    Workspace {
        declaration_id: String,
        fq_name: String,
        rel_path: String,
    },
    External {
        fq_name: String,
        symbol_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetFieldSlotAtomValueRow {
    Class(ClassSetFieldSlotClassRow),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldSlotSourceRow {
    pub rel_path: String,
    pub start_byte: u32,
    pub start_line: u32,
    pub start_byte_column: u32,
    pub end_byte: u32,
    pub end_line: u32,
    pub end_byte_column: u32,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldSlotAtomRow {
    pub value: ClassSetFieldSlotAtomValueRow,
    pub source: ClassSetFieldSlotSourceRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldSlotRow {
    pub owner: ClassSetFieldSlotClassRow,
    pub member: String,
    pub atoms: Vec<ClassSetFieldSlotAtomRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClassSetFieldStoreSurveyRow {
    pub stores: Vec<ClassSetFieldStoreRow>,
    pub unknown_members: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldStoreRow {
    pub owner: Option<ClassSetFieldSlotClassRow>,
    pub member: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetFieldSlotIndexRow {
    pub key: ClassSetFieldSlotIndexKey,
    pub slots: Vec<ClassSetFieldSlotRow>,
    pub artifacts: Vec<ClassSetFieldSlotArtifactRow>,
    pub store_survey: ClassSetFieldStoreSurveyRow,
    content_digest: ClassSetFieldSlotDigest,
}

impl ClassSetFieldSlotIndexRow {
    pub fn try_new(
        key: ClassSetFieldSlotIndexKey,
        slots: Vec<ClassSetFieldSlotRow>,
        artifacts: Vec<ClassSetFieldSlotArtifactRow>,
        store_survey: ClassSetFieldStoreSurveyRow,
    ) -> Result<Self> {
        Self::try_new_cancellable(key, slots, artifacts, store_survey, None)
    }

    fn try_new_cancellable(
        key: ClassSetFieldSlotIndexKey,
        slots: Vec<ClassSetFieldSlotRow>,
        artifacts: Vec<ClassSetFieldSlotArtifactRow>,
        store_survey: ClassSetFieldStoreSurveyRow,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self> {
        ensure_optional_cancellation(cancellation)?;
        if key.language == Language::None || key.representation_version == 0 {
            return Err(StoreError::new("class-set field-slot key is invalid"));
        }
        for slot in &slots {
            ensure_optional_cancellation(cancellation)?;
            validate_class(&slot.owner)?;
            if slot.member.is_empty() || slot.atoms.is_empty() {
                return Err(StoreError::new(
                    "class-set field slot has an empty member or atom set",
                ));
            }
            for atom in &slot.atoms {
                ensure_optional_cancellation(cancellation)?;
                match &atom.value {
                    ClassSetFieldSlotAtomValueRow::Class(class) => validate_class(class)?,
                    ClassSetFieldSlotAtomValueRow::Unknown(reason) if reason.is_empty() => {
                        return Err(StoreError::new(
                            "class-set field-slot unknown reason is empty",
                        ));
                    }
                    ClassSetFieldSlotAtomValueRow::Unknown(_) => {}
                }
                if !valid_rel_path(&atom.source.rel_path)
                    || SourceSpan::new(
                        SourcePosition::new(
                            atom.source.start_byte,
                            atom.source.start_line,
                            atom.source.start_byte_column,
                        ),
                        SourcePosition::new(
                            atom.source.end_byte,
                            atom.source.end_line,
                            atom.source.end_byte_column,
                        ),
                    )
                    .is_err()
                    || !valid_source_kind(&atom.source.kind)
                {
                    return Err(StoreError::new("class-set field-slot source is invalid"));
                }
                if let ClassSetFieldSlotAtomValueRow::Unknown(reason) = &atom.value
                    && !valid_unknown_reason(reason)
                {
                    return Err(StoreError::new(
                        "class-set field-slot unknown reason is invalid",
                    ));
                }
            }
        }
        ensure_optional_cancellation(cancellation)?;
        if slots.windows(2).any(|pair| {
            class_row_order(&pair[0].owner, &pair[1].owner)
                .then_with(|| pair[0].member.cmp(&pair[1].member))
                .is_ge()
        }) || slots.iter().any(|slot| {
            slot.atoms
                .windows(2)
                .any(|pair| atom_row_order(&pair[0], &pair[1]).is_ge())
        }) {
            return Err(StoreError::new(
                "class-set field-slot rows are not canonical",
            ));
        }
        for store in &store_survey.stores {
            ensure_optional_cancellation(cancellation)?;
            if store.member.is_empty() {
                return Err(StoreError::new(
                    "class-set field-store survey has an empty member",
                ));
            }
            if let Some(owner) = &store.owner {
                validate_class(owner)?;
            }
        }
        if store_survey
            .stores
            .windows(2)
            .any(|pair| field_store_row_order(&pair[0], &pair[1]).is_ge())
        {
            return Err(StoreError::new(
                "class-set field-store survey rows are not canonical",
            ));
        }
        if artifacts
            .windows(2)
            .any(|pair| pair[0].rel_path >= pair[1].rel_path)
            || artifacts.iter().any(|artifact| {
                !valid_rel_path(&artifact.rel_path) || artifact.work.source_bytes != 0
            })
        {
            return Err(StoreError::new(
                "class-set field-slot artifact identities are not canonical",
            ));
        }
        enforce_payload_bounds_cancellable(&store_survey, &slots, &artifacts, cancellation)?;
        let mut row = Self {
            key,
            slots,
            artifacts,
            store_survey,
            content_digest: [0; 32],
        };
        row.content_digest = row.canonical_content_digest_cancellable(cancellation)?;
        Ok(row)
    }

    pub const fn content_digest(&self) -> &ClassSetFieldSlotDigest {
        &self.content_digest
    }

    fn canonical_content_digest_cancellable(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ClassSetFieldSlotDigest> {
        let mut hash = FieldSlotDigest::new(b"bifrost-class-set-field-slot-store-v2");
        hash.text(self.key.language.config_label());
        hash.bytes(&self.key.workspace_content_digest);
        hash.bytes(&self.key.provider_behavior_digest);
        hash.bytes(&self.key.active_pack_digest);
        hash.bytes(&self.key.adapter_semantics_digest);
        hash.u64(u64::from(self.key.representation_version));
        hash.u64(self.store_survey.stores.len() as u64);
        for store in &self.store_survey.stores {
            ensure_optional_cancellation(cancellation)?;
            match &store.owner {
                Some(owner) => {
                    hash.tag(1);
                    hash.class(owner);
                }
                None => hash.tag(0),
            }
            hash.text(&store.member);
        }
        hash.tag(u8::from(self.store_survey.unknown_members));
        hash.u64(self.artifacts.len() as u64);
        for artifact in &self.artifacts {
            ensure_optional_cancellation(cancellation)?;
            hash.text(&artifact.rel_path);
            hash.bytes(&artifact.public_digest);
            hash.semantic_work(artifact.work);
        }
        hash.u64(self.slots.len() as u64);
        for slot in &self.slots {
            ensure_optional_cancellation(cancellation)?;
            hash.class(&slot.owner);
            hash.text(&slot.member);
            hash.u64(slot.atoms.len() as u64);
            for atom in &slot.atoms {
                ensure_optional_cancellation(cancellation)?;
                match &atom.value {
                    ClassSetFieldSlotAtomValueRow::Class(class) => {
                        hash.tag(0);
                        hash.class(class);
                    }
                    ClassSetFieldSlotAtomValueRow::Unknown(reason) => {
                        hash.tag(1);
                        hash.text(reason);
                    }
                }
                hash.text(&atom.source.rel_path);
                hash.u64(u64::from(atom.source.start_byte));
                hash.u64(u64::from(atom.source.start_line));
                hash.u64(u64::from(atom.source.start_byte_column));
                hash.u64(u64::from(atom.source.end_byte));
                hash.u64(u64::from(atom.source.end_line));
                hash.u64(u64::from(atom.source.end_byte_column));
                hash.text(&atom.source.kind);
            }
        }
        Ok(hash.finish())
    }
}

fn class_row_order(
    left: &ClassSetFieldSlotClassRow,
    right: &ClassSetFieldSlotClassRow,
) -> std::cmp::Ordering {
    match (left, right) {
        (
            ClassSetFieldSlotClassRow::Workspace {
                declaration_id: left_id,
                fq_name: left_name,
                rel_path: left_path,
            },
            ClassSetFieldSlotClassRow::Workspace {
                declaration_id: right_id,
                fq_name: right_name,
                rel_path: right_path,
            },
        ) => left_name
            .cmp(right_name)
            .then_with(|| left_path.cmp(right_path))
            .then_with(|| left_id.cmp(right_id)),
        (ClassSetFieldSlotClassRow::Workspace { .. }, _) => std::cmp::Ordering::Less,
        (_, ClassSetFieldSlotClassRow::Workspace { .. }) => std::cmp::Ordering::Greater,
        (
            ClassSetFieldSlotClassRow::External {
                fq_name: left_name,
                symbol_id: left_id,
            },
            ClassSetFieldSlotClassRow::External {
                fq_name: right_name,
                symbol_id: right_id,
            },
        ) => left_name
            .cmp(right_name)
            .then_with(|| left_id.cmp(right_id)),
    }
}

fn field_store_row_order(
    left: &ClassSetFieldStoreRow,
    right: &ClassSetFieldStoreRow,
) -> std::cmp::Ordering {
    match (&left.owner, &right.owner) {
        (None, None) => left.member.cmp(&right.member),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(left_owner), Some(right_owner)) => {
            class_row_order(left_owner, right_owner).then_with(|| left.member.cmp(&right.member))
        }
    }
}

fn atom_row_order(
    left: &ClassSetFieldSlotAtomRow,
    right: &ClassSetFieldSlotAtomRow,
) -> std::cmp::Ordering {
    let value = match (&left.value, &right.value) {
        (
            ClassSetFieldSlotAtomValueRow::Class(left),
            ClassSetFieldSlotAtomValueRow::Class(right),
        ) => class_row_order(left, right),
        (ClassSetFieldSlotAtomValueRow::Class(_), ClassSetFieldSlotAtomValueRow::Unknown(_)) => {
            std::cmp::Ordering::Less
        }
        (ClassSetFieldSlotAtomValueRow::Unknown(_), ClassSetFieldSlotAtomValueRow::Class(_)) => {
            std::cmp::Ordering::Greater
        }
        (
            ClassSetFieldSlotAtomValueRow::Unknown(left),
            ClassSetFieldSlotAtomValueRow::Unknown(right),
        ) => left.cmp(right),
    };
    value
        .then_with(|| left.source.rel_path.cmp(&right.source.rel_path))
        .then_with(|| left.source.start_byte.cmp(&right.source.start_byte))
        .then_with(|| left.source.end_byte.cmp(&right.source.end_byte))
        .then_with(|| left.source.kind.cmp(&right.source.kind))
}

fn valid_source_kind(kind: &str) -> bool {
    matches!(
        kind,
        "constructor_call"
            | "literal"
            | "container_literal"
            | "declared_parameter"
            | "root_receiver"
            | "unknown"
    )
}

fn valid_unknown_reason(reason: &str) -> bool {
    matches!(
        reason,
        "root_parameter"
            | "self_receiver"
            | "variadic_parameter"
            | "unresolved_call"
            | "truncated"
            | "unmodeled_load"
            | "await"
            | "capture"
            | "ambiguous_callee"
            | "external_not_modeled"
            | "unresolved_base"
            | "dynamic_attributes"
            | "pack_incomplete"
            | "uncertain_flow"
            | "field_slot_incomplete"
            | "dynamic_field_write"
            | "solver_budget"
            | "semantic_budget"
            | "incomplete_root"
            | "open_type_bound"
            | "scalar_receiver"
            | "class_creation"
            | "class_object"
    )
}

fn validate_class(class: &ClassSetFieldSlotClassRow) -> Result<()> {
    match class {
        ClassSetFieldSlotClassRow::Workspace {
            declaration_id,
            fq_name,
            rel_path,
        } if !declaration_id.is_empty() && !fq_name.is_empty() && valid_rel_path(rel_path) => {
            Ok(())
        }
        ClassSetFieldSlotClassRow::External { fq_name, symbol_id }
            if !fq_name.is_empty() && !symbol_id.is_empty() =>
        {
            Ok(())
        }
        _ => Err(StoreError::new("class-set field-slot class is invalid")),
    }
}

fn valid_rel_path(path: &str) -> bool {
    WorkspaceRelativePath::try_from_path(Path::new(path))
        .is_ok_and(|normalized| normalized.as_str() == path)
}

fn payload_text_bytes_cancellable(
    store_survey: &ClassSetFieldStoreSurveyRow,
    slots: &[ClassSetFieldSlotRow],
    artifacts: &[ClassSetFieldSlotArtifactRow],
    cancellation: Option<&CancellationToken>,
) -> Result<usize> {
    fn checked_add(left: usize, right: usize) -> Result<usize> {
        left.checked_add(right).ok_or_else(|| {
            StoreError::resource_bound("class-set field-slot payload text size overflows usize")
        })
    }

    fn class_bytes(class: &ClassSetFieldSlotClassRow) -> Result<usize> {
        match class {
            ClassSetFieldSlotClassRow::Workspace {
                declaration_id,
                fq_name,
                rel_path,
            } => checked_add(
                checked_add(declaration_id.len(), fq_name.len())?,
                rel_path.len(),
            ),
            ClassSetFieldSlotClassRow::External { fq_name, symbol_id } => {
                checked_add(fq_name.len(), symbol_id.len())
            }
        }
    }

    let mut total = 0usize;
    for artifact in artifacts {
        ensure_optional_cancellation(cancellation)?;
        total = checked_add(total, artifact.rel_path.len())?;
    }
    for store in &store_survey.stores {
        ensure_optional_cancellation(cancellation)?;
        if let Some(owner) = &store.owner {
            total = checked_add(total, class_bytes(owner)?)?;
        }
        total = checked_add(total, store.member.len())?;
    }
    for slot in slots {
        ensure_optional_cancellation(cancellation)?;
        total = checked_add(total, class_bytes(&slot.owner)?)?;
        total = checked_add(total, slot.member.len())?;
        for atom in &slot.atoms {
            ensure_optional_cancellation(cancellation)?;
            let value_bytes = match &atom.value {
                ClassSetFieldSlotAtomValueRow::Class(class) => class_bytes(class)?,
                ClassSetFieldSlotAtomValueRow::Unknown(reason) => reason.len(),
            };
            total = checked_add(total, value_bytes)?;
            total = checked_add(total, atom.source.rel_path.len())?;
            total = checked_add(total, atom.source.kind.len())?;
        }
    }
    Ok(total)
}

fn enforce_payload_bounds_cancellable(
    store_survey: &ClassSetFieldStoreSurveyRow,
    slots: &[ClassSetFieldSlotRow],
    artifacts: &[ClassSetFieldSlotArtifactRow],
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    ensure_optional_cancellation(cancellation)?;
    if slots.len() > MAX_FIELD_SLOTS {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot count exceeds {MAX_FIELD_SLOTS}"
        )));
    }
    if artifacts.len() > MAX_FIELD_SLOT_ARTIFACTS {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot artifact count exceeds {MAX_FIELD_SLOT_ARTIFACTS}"
        )));
    }
    if store_survey.stores.len() > MAX_FIELD_SLOT_STORES {
        return Err(StoreError::resource_bound(format!(
            "class-set field-store survey count exceeds {MAX_FIELD_SLOT_STORES}"
        )));
    }
    let atom_count = slots.iter().try_fold(0usize, |total, slot| {
        ensure_optional_cancellation(cancellation)?;
        total.checked_add(slot.atoms.len()).ok_or_else(|| {
            StoreError::resource_bound("class-set field-slot atom count overflows usize")
        })
    })?;
    if atom_count > MAX_FIELD_SLOT_ATOMS {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot atom count exceeds {MAX_FIELD_SLOT_ATOMS}"
        )));
    }
    enforce_declared_payload_bounds(
        store_survey.stores.len(),
        slots.len(),
        atom_count,
        artifacts.len(),
        payload_text_bytes_cancellable(store_survey, slots, artifacts, cancellation)?,
    )
}

fn enforce_declared_payload_bounds(
    store_count: usize,
    slot_count: usize,
    atom_count: usize,
    artifact_count: usize,
    text_bytes: usize,
) -> Result<()> {
    let fixed_bytes = store_count
        .checked_mul(std::mem::size_of::<ClassSetFieldStoreRow>())
        .and_then(|stores| {
            slot_count
                .checked_mul(std::mem::size_of::<ClassSetFieldSlotRow>())
                .and_then(|slots| stores.checked_add(slots))
        })
        .and_then(|bytes| {
            atom_count
                .checked_mul(std::mem::size_of::<ClassSetFieldSlotAtomRow>())
                .and_then(|atoms| bytes.checked_add(atoms))
        })
        .and_then(|bytes| {
            artifact_count
                .checked_mul(std::mem::size_of::<ClassSetFieldSlotArtifactRow>())
                .and_then(|artifacts| bytes.checked_add(artifacts))
        })
        .and_then(|bytes| bytes.checked_add(text_bytes))
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| {
            StoreError::resource_bound("class-set field-slot retained size overflows usize")
        })?;
    if fixed_bytes > MAX_FIELD_SLOT_RETAINED_BYTES {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot retained size exceeds {MAX_FIELD_SLOT_RETAINED_BYTES} bytes"
        )));
    }
    Ok(())
}

struct FieldSlotDigest(Sha256);

impl FieldSlotDigest {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Self(Sha256::new());
        hash.bytes(domain);
        hash
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn tag(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn class(&mut self, class: &ClassSetFieldSlotClassRow) {
        match class {
            ClassSetFieldSlotClassRow::Workspace {
                declaration_id,
                fq_name,
                rel_path,
            } => {
                self.tag(0);
                self.text(declaration_id);
                self.text(fq_name);
                self.text(rel_path);
            }
            ClassSetFieldSlotClassRow::External { fq_name, symbol_id } => {
                self.tag(1);
                self.text(fq_name);
                self.text(symbol_id);
            }
        }
    }

    fn semantic_work(&mut self, work: SemanticWork) {
        for amount in semantic_work_values(work) {
            self.u64(amount as u64);
        }
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

const MAX_FIELD_SLOTS: usize = 262_144;
const MAX_FIELD_SLOT_ATOMS: usize = 262_144;
const MAX_FIELD_SLOT_ARTIFACTS: usize = 262_144;
const MAX_FIELD_SLOT_STORES: usize = 262_144;
const MAX_FIELD_SLOT_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELD_SLOT_TEXT_BYTES: usize = MAX_FIELD_SLOT_RETAINED_BYTES;

pub(crate) const CLASS_SET_FIELD_SLOT_INDEX_SQL: &str = "SELECT index_id,
            CASE WHEN length(content_digest)=32 THEN content_digest END,
            slot_count,atom_count,artifact_count,payload_text_bytes,
            store_survey_count,store_survey_unknown_members
     FROM class_set_field_slot_indexes
     WHERE lang=?1 AND workspace_content_digest=?2
       AND provider_behavior_digest=?3 AND active_pack_digest=?4
       AND adapter_semantics_digest=?5 AND representation_version=?6
       AND completion='complete'";

pub(crate) const CLASS_SET_FIELD_SLOTS_SQL: &str =
    "SELECT length(CAST(COALESCE(owner_declaration_id,'') AS BLOB))
              + length(CAST(owner_fq_name AS BLOB))
              + length(CAST(COALESCE(owner_rel_path,'') AS BLOB))
              + length(CAST(COALESCE(owner_symbol_id,'') AS BLOB))
              + length(CAST(member AS BLOB)),
            slot_ordinal,owner_kind,owner_declaration_id,owner_fq_name,
            owner_rel_path,owner_symbol_id,member
     FROM class_set_field_slots WHERE index_id=?1 ORDER BY slot_ordinal LIMIT ?2";

pub(crate) const CLASS_SET_FIELD_SLOT_STORES_SQL: &str =
    "SELECT length(CAST(COALESCE(owner_declaration_id,'') AS BLOB))
              + length(CAST(COALESCE(owner_fq_name,'') AS BLOB))
              + length(CAST(COALESCE(owner_rel_path,'') AS BLOB))
              + length(CAST(COALESCE(owner_symbol_id,'') AS BLOB))
              + length(CAST(member AS BLOB)),
            store_ordinal,owner_kind,owner_declaration_id,owner_fq_name,
            owner_rel_path,owner_symbol_id,member
     FROM class_set_field_slot_stores WHERE index_id=?1
     ORDER BY store_ordinal LIMIT ?2";

pub(crate) const CLASS_SET_FIELD_SLOT_ATOMS_SQL: &str =
    "SELECT length(CAST(COALESCE(class_declaration_id,'') AS BLOB))
              + length(CAST(COALESCE(class_fq_name,'') AS BLOB))
              + length(CAST(COALESCE(class_rel_path,'') AS BLOB))
              + length(CAST(COALESCE(class_symbol_id,'') AS BLOB))
              + length(CAST(COALESCE(unknown_reason,'') AS BLOB))
              + length(CAST(source_rel_path AS BLOB))
              + length(CAST(source_kind AS BLOB)),
            slot_ordinal,atom_ordinal,atom_kind,class_declaration_id,class_fq_name,
            class_rel_path,class_symbol_id,unknown_reason,source_rel_path,
            source_start_byte,source_start_line,source_start_byte_column,
            source_end_byte,source_end_line,source_end_byte_column,source_kind
     FROM class_set_field_slot_atoms WHERE index_id=?1
     ORDER BY slot_ordinal,atom_ordinal LIMIT ?2";

pub(crate) const CLASS_SET_FIELD_SLOT_ARTIFACTS_SQL: &str =
    "SELECT length(CAST(artifact_rel_path AS BLOB)),
            artifact_ordinal,artifact_rel_path,
            CASE WHEN length(artifact_public_digest)=32 THEN artifact_public_digest END,
            source_bytes,procedures,blocks,program_points,values_count,allocations,call_sites,
            memory_locations,captures,source_mappings,evidence,gaps,events,control_edges,
            nested_entries,owned_text_bytes
     FROM class_set_field_slot_artifacts WHERE index_id=?1 ORDER BY artifact_ordinal LIMIT ?2";

pub(crate) const PRUNE_OLD_CLASS_SET_FIELD_SLOT_INDEXES_SQL: &str =
    "DELETE FROM class_set_field_slot_indexes
     WHERE lang=?1 AND index_id NOT IN (
       SELECT index_id FROM class_set_field_slot_indexes
       WHERE lang=?1 ORDER BY published_at DESC,index_id DESC LIMIT 8
     )";

impl AnalyzerStore {
    /// Inject an operational failure at the public field-slot store boundary.
    ///
    /// This is deliberately scoped to test-support builds so flow/RQL tests can
    /// prove that a durable-store outage neither publishes a ready in-memory
    /// value nor masquerades as corrupt persisted evidence.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn set_class_set_field_slot_operational_failure_for_test(&self, fail: bool) {
        self.class_set_field_slot_operational_failure
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn reject_injected_class_set_field_slot_operation_for_test(&self) -> Result<()> {
        if self
            .class_set_field_slot_operational_failure
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::new(
                "injected class-set field-slot operational failure",
            ));
        }
        Ok(())
    }

    pub fn class_set_field_slot_index(
        &self,
        key: &ClassSetFieldSlotIndexKey,
        cancellation: &CancellationToken,
    ) -> Result<Option<ClassSetFieldSlotIndexRow>> {
        #[cfg(any(test, feature = "test-support"))]
        self.reject_injected_class_set_field_slot_operation_for_test()?;
        ensure_not_cancelled(cancellation)?;
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = load_index(&tx, key, cancellation)?;
        ensure_not_cancelled(cancellation)?;
        tx.commit()?;
        Ok(row)
    }

    pub fn publish_class_set_field_slot_index(
        &self,
        row: ClassSetFieldSlotIndexRow,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        #[cfg(any(test, feature = "test-support"))]
        self.reject_injected_class_set_field_slot_operation_for_test()?;
        ensure_not_cancelled(cancellation)?;
        enforce_payload_bounds_cancellable(
            &row.store_survey,
            &row.slots,
            &row.artifacts,
            Some(cancellation),
        )?;
        if row.content_digest != row.canonical_content_digest_cancellable(Some(cancellation))? {
            return Err(StoreError::new(
                "class-set field-slot index changed after construction",
            ));
        }
        self.conn.execute({
            let cancellation = cancellation.clone();
            move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure_not_cancelled(&cancellation)?;
                match load_index(&tx, &row.key, &cancellation) {
                    Ok(Some(existing)) if existing == row => {
                        tx.commit()?;
                        return Ok(false);
                    }
                    Ok(Some(existing)) => {
                        return Err(different_complete_content(&existing, &row));
                    }
                    Ok(None) => {}
                    Err(error) if error.is_corrupt() || error.is_resource_bound() => {
                        tx.execute(
                            "DELETE FROM class_set_field_slot_indexes
                             WHERE lang=?1 AND workspace_content_digest=?2
                                AND provider_behavior_digest=?3 AND active_pack_digest=?4
                               AND adapter_semantics_digest=?5 AND representation_version=?6",
                            params![
                                row.key.language.config_label(),
                                row.key.workspace_content_digest.as_slice(),
                                row.key.provider_behavior_digest.as_slice(),
                                row.key.active_pack_digest.as_slice(),
                                row.key.adapter_semantics_digest.as_slice(),
                                row.key.representation_version,
                            ],
                        )?;
                    }
                    Err(error) => return Err(error),
                }
                insert_index(&tx, &row, &cancellation)?;
                ensure_not_cancelled(&cancellation)?;
                if load_index(&tx, &row.key, &cancellation)?.as_ref() != Some(&row) {
                    return Err(StoreError::new(
                        "published class-set field-slot index failed validation",
                    ));
                }
                tx.execute(
                    PRUNE_OLD_CLASS_SET_FIELD_SLOT_INDEXES_SQL,
                    params![row.key.language.config_label()],
                )?;
                ensure_not_cancelled(&cancellation)?;
                tx.commit()?;
                Ok(true)
            }
        })
    }
}

fn different_complete_content(
    existing: &ClassSetFieldSlotIndexRow,
    candidate: &ClassSetFieldSlotIndexRow,
) -> StoreError {
    let artifact_identities_differ = existing.artifacts.len() != candidate.artifacts.len()
        || existing
            .artifacts
            .iter()
            .zip(&candidate.artifacts)
            .any(|(left, right)| {
                left.rel_path != right.rel_path || left.public_digest != right.public_digest
            });
    let artifact_work_differ = existing.artifacts.len() != candidate.artifacts.len()
        || existing
            .artifacts
            .iter()
            .zip(&candidate.artifacts)
            .any(|(left, right)| left.work != right.work);
    StoreError::new(format!(
        "class-set field-slot key names different complete content: \
         existing_digest={} candidate_digest={} artifact_identities_differ={} \
         artifact_work_differ={} slots_differ={} store_survey_differ={}",
        StableDigest::from_array(*existing.content_digest()),
        StableDigest::from_array(*candidate.content_digest()),
        artifact_identities_differ,
        artifact_work_differ,
        existing.slots != candidate.slots,
        existing.store_survey != candidate.store_survey,
    ))
}

fn load_index(
    conn: &rusqlite::Connection,
    key: &ClassSetFieldSlotIndexKey,
    cancellation: &CancellationToken,
) -> Result<Option<ClassSetFieldSlotIndexRow>> {
    ensure_not_cancelled(cancellation)?;
    let header = conn
        .query_row(
            CLASS_SET_FIELD_SLOT_INDEX_SQL,
            params![
                key.language.config_label(),
                key.workspace_content_digest.as_slice(),
                key.provider_behavior_digest.as_slice(),
                key.active_pack_digest.as_slice(),
                key.adapter_semantics_digest.as_slice(),
                key.representation_version,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    ensure_not_cancelled(cancellation)?;
    let Some((
        index_id,
        content_digest,
        slot_count,
        atom_count,
        artifact_count,
        text_bytes,
        store_count,
        unknown_members,
    )) = header
    else {
        return Ok(None);
    };
    let content_digest = content_digest.ok_or_else(|| {
        StoreError::corrupt("class-set field-slot content digest size is corrupt")
    })?;
    let slot_count = bounded_count(slot_count, MAX_FIELD_SLOTS, "slot")?;
    let atom_count = bounded_count(atom_count, MAX_FIELD_SLOT_ATOMS, "atom")?;
    let artifact_count = bounded_count(artifact_count, MAX_FIELD_SLOT_ARTIFACTS, "artifact")?;
    let store_count = bounded_count(store_count, MAX_FIELD_SLOT_STORES, "store survey")?;
    let text_bytes = bounded_count(text_bytes, MAX_FIELD_SLOT_TEXT_BYTES, "payload text byte")?;
    enforce_declared_payload_bounds(
        store_count,
        slot_count,
        atom_count,
        artifact_count,
        text_bytes,
    )?;
    let unknown_members = bool_value(unknown_members, "store survey unknown-members bit")?;
    let mut actual_text_bytes = 0usize;
    let stores = load_store_survey(
        conn,
        index_id,
        store_count,
        &mut actual_text_bytes,
        cancellation,
    )?;
    let mut artifacts = load_artifacts(
        conn,
        index_id,
        artifact_count,
        &mut actual_text_bytes,
        cancellation,
    )?;
    let mut slots = load_slots(
        conn,
        index_id,
        slot_count,
        atom_count,
        &mut actual_text_bytes,
        cancellation,
    )?;
    let store_survey = ClassSetFieldStoreSurveyRow {
        stores,
        unknown_members,
    };
    if actual_text_bytes != text_bytes
        || payload_text_bytes_cancellable(&store_survey, &slots, &artifacts, Some(cancellation))?
            != text_bytes
    {
        return Err(StoreError::corrupt(
            "class-set field-slot payload text size is corrupt",
        ));
    }
    artifacts.shrink_to_fit();
    for slot in &mut slots {
        slot.atoms.shrink_to_fit();
    }
    slots.shrink_to_fit();
    let row = ClassSetFieldSlotIndexRow::try_new_cancellable(
        key.clone(),
        slots,
        artifacts,
        store_survey,
        Some(cancellation),
    )
    .map_err(|error| {
        if cancellation.is_cancelled() || error.is_resource_bound() {
            error
        } else {
            StoreError::corrupt(format!("invalid persisted class-set field slots: {error}"))
        }
    })?;
    if row.content_digest != digest(content_digest, "content")? {
        return Err(StoreError::corrupt(
            "class-set field-slot content digest is corrupt",
        ));
    }
    Ok(Some(row))
}

fn load_store_survey(
    conn: &rusqlite::Connection,
    index_id: i64,
    store_count: usize,
    actual_text_bytes: &mut usize,
    cancellation: &CancellationToken,
) -> Result<Vec<ClassSetFieldStoreRow>> {
    let limit = i64::try_from(store_count.saturating_add(1))
        .map_err(|_| StoreError::new("class-set field-store survey limit exceeds i64"))?;
    let mut statement = conn.prepare_cached(CLASS_SET_FIELD_SLOT_STORES_SQL)?;
    let mut rows = statement.query(params![index_id, limit])?;
    let mut stores = Vec::new();
    while let Some(row) = rows.next()? {
        ensure_not_cancelled(cancellation)?;
        admit_text_bytes(actual_text_bytes, row.get(0)?)?;
        let ordinal = row.get::<_, i64>(1)?;
        if ordinal != stores.len() as i64 {
            return Err(StoreError::corrupt(
                "class-set field-store survey ordinals are not dense",
            ));
        }
        let owner_kind = row.get::<_, Option<String>>(2)?;
        let declaration_id = row.get::<_, Option<String>>(3)?;
        let fq_name = row.get::<_, Option<String>>(4)?;
        let rel_path = row.get::<_, Option<String>>(5)?;
        let symbol_id = row.get::<_, Option<String>>(6)?;
        let owner = match owner_kind.as_deref() {
            None => {
                if declaration_id.is_some()
                    || fq_name.is_some()
                    || rel_path.is_some()
                    || symbol_id.is_some()
                {
                    return Err(StoreError::corrupt(
                        "unattributed field-store survey row has owner columns",
                    ));
                }
                None
            }
            Some("workspace") => Some(workspace_class(
                declaration_id,
                fq_name,
                rel_path,
                symbol_id,
            )?),
            Some("external") => Some(external_class(
                declaration_id,
                fq_name,
                rel_path,
                symbol_id,
            )?),
            Some(_) => {
                return Err(StoreError::corrupt(
                    "class-set field-store survey owner kind is corrupt",
                ));
            }
        };
        stores.push(ClassSetFieldStoreRow {
            owner,
            member: row.get(7)?,
        });
    }
    if stores.len() != store_count {
        return Err(StoreError::corrupt(
            "class-set field-store survey count is corrupt",
        ));
    }
    Ok(stores)
}

fn load_artifacts(
    conn: &rusqlite::Connection,
    index_id: i64,
    artifact_count: usize,
    actual_text_bytes: &mut usize,
    cancellation: &CancellationToken,
) -> Result<Vec<ClassSetFieldSlotArtifactRow>> {
    let limit = i64::try_from(artifact_count.saturating_add(1))
        .map_err(|_| StoreError::new("class-set field-slot artifact limit exceeds i64"))?;
    let mut statement = conn.prepare_cached(CLASS_SET_FIELD_SLOT_ARTIFACTS_SQL)?;
    let mut rows = statement.query(params![index_id, limit])?;
    let mut artifacts = Vec::new();
    while let Some(row) = rows.next()? {
        ensure_not_cancelled(cancellation)?;
        admit_text_bytes(actual_text_bytes, row.get(0)?)?;
        let ordinal = row.get::<_, i64>(1)?;
        if ordinal != artifacts.len() as i64 {
            return Err(StoreError::corrupt(
                "class-set field-slot artifact ordinals are not dense",
            ));
        }
        artifacts.push(ClassSetFieldSlotArtifactRow {
            rel_path: row.get(2)?,
            public_digest: digest(
                row.get::<_, Option<Vec<u8>>>(3)?.ok_or_else(|| {
                    StoreError::corrupt("class-set field-slot artifact digest size is corrupt")
                })?,
                "artifact",
            )?,
            work: semantic_work_from_values(
                &(4..20)
                    .map(|column| row.get::<_, i64>(column))
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )?,
        });
    }
    if artifacts.len() != artifact_count {
        return Err(StoreError::corrupt(
            "class-set field-slot artifact count is corrupt",
        ));
    }
    Ok(artifacts)
}

fn load_slots(
    conn: &rusqlite::Connection,
    index_id: i64,
    slot_count: usize,
    atom_count: usize,
    actual_text_bytes: &mut usize,
    cancellation: &CancellationToken,
) -> Result<Vec<ClassSetFieldSlotRow>> {
    let slot_limit = i64::try_from(slot_count.saturating_add(1))
        .map_err(|_| StoreError::new("class-set field-slot limit exceeds i64"))?;
    let mut statement = conn.prepare_cached(CLASS_SET_FIELD_SLOTS_SQL)?;
    let mut slot_rows = statement.query(params![index_id, slot_limit])?;
    let mut slots = Vec::new();
    while let Some(row) = slot_rows.next()? {
        ensure_not_cancelled(cancellation)?;
        admit_text_bytes(actual_text_bytes, row.get(0)?)?;
        let ordinal = row.get::<_, i64>(1)?;
        if ordinal != slots.len() as i64 {
            return Err(StoreError::corrupt(
                "class-set field-slot ordinals are not dense",
            ));
        }
        let owner_kind = row.get::<_, String>(2)?;
        let declaration_id = row.get::<_, Option<String>>(3)?;
        let fq_name = row.get::<_, String>(4)?;
        let rel_path = row.get::<_, Option<String>>(5)?;
        let symbol_id = row.get::<_, Option<String>>(6)?;
        let owner = match owner_kind.as_str() {
            "workspace" => workspace_class(declaration_id, Some(fq_name), rel_path, symbol_id)?,
            "external" => external_class(declaration_id, Some(fq_name), rel_path, symbol_id)?,
            _ => {
                return Err(StoreError::corrupt(
                    "class-set field-slot owner kind is corrupt",
                ));
            }
        };
        slots.push(ClassSetFieldSlotRow {
            owner,
            member: row.get(7)?,
            atoms: Vec::new(),
        });
    }
    if slots.len() != slot_count {
        return Err(StoreError::corrupt("class-set field-slot count is corrupt"));
    }

    let atom_limit = i64::try_from(atom_count.saturating_add(1))
        .map_err(|_| StoreError::new("class-set field-slot atom limit exceeds i64"))?;
    let mut atom_statement = conn.prepare_cached(CLASS_SET_FIELD_SLOT_ATOMS_SQL)?;
    let mut atom_rows = atom_statement.query(params![index_id, atom_limit])?;
    let mut loaded_atoms = 0usize;
    while let Some(row) = atom_rows.next()? {
        ensure_not_cancelled(cancellation)?;
        admit_text_bytes(actual_text_bytes, row.get(0)?)?;
        let slot_ordinal = row.get(1)?;
        let slot = dense_index(slot_ordinal, slot_count, "atom slot")?;
        let atom_ordinal = row.get::<_, i64>(2)?;
        if atom_ordinal != slots[slot].atoms.len() as i64 {
            return Err(StoreError::corrupt(
                "class-set field-slot atom ordinals are not dense",
            ));
        }
        let atom_kind = row.get::<_, String>(3)?;
        let declaration_id = row.get::<_, Option<String>>(4)?;
        let fq_name = row.get::<_, Option<String>>(5)?;
        let rel_path = row.get::<_, Option<String>>(6)?;
        let symbol_id = row.get::<_, Option<String>>(7)?;
        let unknown_reason = row.get::<_, Option<String>>(8)?;
        let value = match atom_kind.as_str() {
            "workspace" => ClassSetFieldSlotAtomValueRow::Class(workspace_class(
                declaration_id,
                fq_name,
                rel_path,
                symbol_id,
            )?),
            "external" => ClassSetFieldSlotAtomValueRow::Class(external_class(
                declaration_id,
                fq_name,
                rel_path,
                symbol_id,
            )?),
            "unknown" => {
                if declaration_id.is_some()
                    || fq_name.is_some()
                    || rel_path.is_some()
                    || symbol_id.is_some()
                {
                    return Err(StoreError::corrupt(
                        "class-set field-slot unknown atom has class columns",
                    ));
                }
                ClassSetFieldSlotAtomValueRow::Unknown(unknown_reason.ok_or_else(|| {
                    StoreError::corrupt("class-set field-slot unknown atom has no reason")
                })?)
            }
            _ => {
                return Err(StoreError::corrupt(
                    "class-set field-slot atom kind is corrupt",
                ));
            }
        };
        slots[slot].atoms.push(ClassSetFieldSlotAtomRow {
            value,
            source: ClassSetFieldSlotSourceRow {
                rel_path: row.get(9)?,
                start_byte: u32_value(row.get(10)?, "source start")?,
                start_line: u32_value(row.get(11)?, "source start line")?,
                start_byte_column: u32_value(row.get(12)?, "source start byte column")?,
                end_byte: u32_value(row.get(13)?, "source end")?,
                end_line: u32_value(row.get(14)?, "source end line")?,
                end_byte_column: u32_value(row.get(15)?, "source end byte column")?,
                kind: row.get(16)?,
            },
        });
        loaded_atoms = loaded_atoms.saturating_add(1);
    }
    if loaded_atoms != atom_count {
        return Err(StoreError::corrupt(
            "class-set field-slot atom count is corrupt",
        ));
    }
    Ok(slots)
}

fn workspace_class(
    declaration_id: Option<String>,
    fq_name: Option<String>,
    rel_path: Option<String>,
    symbol_id: Option<String>,
) -> Result<ClassSetFieldSlotClassRow> {
    if symbol_id.is_some() {
        return Err(StoreError::corrupt(
            "workspace field-slot class has an external symbol ID",
        ));
    }
    Ok(ClassSetFieldSlotClassRow::Workspace {
        declaration_id: declaration_id.ok_or_else(|| {
            StoreError::corrupt("workspace field-slot class has no declaration ID")
        })?,
        fq_name: fq_name
            .ok_or_else(|| StoreError::corrupt("workspace field-slot class has no name"))?,
        rel_path: rel_path
            .ok_or_else(|| StoreError::corrupt("workspace field-slot class has no path"))?,
    })
}

fn external_class(
    declaration_id: Option<String>,
    fq_name: Option<String>,
    rel_path: Option<String>,
    symbol_id: Option<String>,
) -> Result<ClassSetFieldSlotClassRow> {
    if declaration_id.is_some() || rel_path.is_some() {
        return Err(StoreError::corrupt(
            "external field-slot class has workspace identity columns",
        ));
    }
    Ok(ClassSetFieldSlotClassRow::External {
        fq_name: fq_name
            .ok_or_else(|| StoreError::corrupt("external field-slot class has no name"))?,
        symbol_id: symbol_id
            .ok_or_else(|| StoreError::corrupt("external field-slot class has no symbol ID"))?,
    })
}

fn insert_index(
    conn: &rusqlite::Connection,
    row: &ClassSetFieldSlotIndexRow,
    cancellation: &CancellationToken,
) -> Result<i64> {
    let atom_count = row.slots.iter().try_fold(0usize, |total, slot| {
        total.checked_add(slot.atoms.len()).ok_or_else(|| {
            StoreError::resource_bound("class-set field-slot atom count overflows usize")
        })
    })?;
    conn.execute(
        "INSERT INTO class_set_field_slot_indexes(
           lang,workspace_content_digest,provider_behavior_digest,active_pack_digest,
         adapter_semantics_digest,representation_version,content_digest,slot_count,atom_count,
           artifact_count,payload_text_bytes,store_survey_count,store_survey_unknown_members,
           completion,published_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'complete',unixepoch())",
        params![
            row.key.language.config_label(),
            row.key.workspace_content_digest.as_slice(),
            row.key.provider_behavior_digest.as_slice(),
            row.key.active_pack_digest.as_slice(),
            row.key.adapter_semantics_digest.as_slice(),
            row.key.representation_version,
            row.content_digest.as_slice(),
            row.slots.len(),
            atom_count,
            row.artifacts.len(),
            payload_text_bytes_cancellable(
                &row.store_survey,
                &row.slots,
                &row.artifacts,
                Some(cancellation),
            )?,
            row.store_survey.stores.len(),
            i64::from(row.store_survey.unknown_members),
        ],
    )?;
    let index_id = conn.last_insert_rowid();
    for (store_ordinal, store) in row.store_survey.stores.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        let owner = store.owner.as_ref().map(class_columns);
        conn.execute(
            "INSERT INTO class_set_field_slot_stores VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                index_id,
                store_ordinal,
                owner.as_ref().map(|columns| columns.kind),
                owner.as_ref().and_then(|columns| columns.declaration_id),
                owner.as_ref().map(|columns| columns.fq_name),
                owner.as_ref().and_then(|columns| columns.rel_path),
                owner.as_ref().and_then(|columns| columns.symbol_id),
                &store.member,
            ],
        )?;
    }
    for (artifact_ordinal, artifact) in row.artifacts.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        let artifact_work = semantic_work_values(artifact.work);
        conn.execute(
            "INSERT INTO class_set_field_slot_artifacts VALUES(
               ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
            params![
                index_id,
                artifact_ordinal,
                &artifact.rel_path,
                artifact.public_digest.as_slice(),
                artifact_work[0],
                artifact_work[1],
                artifact_work[2],
                artifact_work[3],
                artifact_work[4],
                artifact_work[5],
                artifact_work[6],
                artifact_work[7],
                artifact_work[8],
                artifact_work[9],
                artifact_work[10],
                artifact_work[11],
                artifact_work[12],
                artifact_work[13],
                artifact_work[14],
                artifact_work[15],
            ],
        )?;
    }
    for (slot_ordinal, slot) in row.slots.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        let owner = class_columns(&slot.owner);
        conn.execute(
            "INSERT INTO class_set_field_slots VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                index_id,
                slot_ordinal,
                owner.kind,
                owner.declaration_id,
                owner.fq_name,
                owner.rel_path,
                owner.symbol_id,
                &slot.member,
            ],
        )?;
        for (atom_ordinal, atom) in slot.atoms.iter().enumerate() {
            ensure_not_cancelled(cancellation)?;
            let (kind, class, reason) = match &atom.value {
                ClassSetFieldSlotAtomValueRow::Class(class) => {
                    let columns = class_columns(class);
                    (columns.kind, Some(columns), None)
                }
                ClassSetFieldSlotAtomValueRow::Unknown(reason) => {
                    ("unknown", None, Some(reason.as_str()))
                }
            };
            conn.execute(
                "INSERT INTO class_set_field_slot_atoms VALUES(
                   ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    index_id,
                    slot_ordinal,
                    atom_ordinal,
                    kind,
                    class.as_ref().and_then(|columns| columns.declaration_id),
                    class.as_ref().map(|columns| columns.fq_name),
                    class.as_ref().and_then(|columns| columns.rel_path),
                    class.as_ref().and_then(|columns| columns.symbol_id),
                    reason,
                    &atom.source.rel_path,
                    atom.source.start_byte,
                    atom.source.start_line,
                    atom.source.start_byte_column,
                    atom.source.end_byte,
                    atom.source.end_line,
                    atom.source.end_byte_column,
                    &atom.source.kind,
                ],
            )?;
        }
    }
    Ok(index_id)
}

struct ClassColumns<'a> {
    kind: &'static str,
    declaration_id: Option<&'a str>,
    fq_name: &'a str,
    rel_path: Option<&'a str>,
    symbol_id: Option<&'a str>,
}

fn class_columns(class: &ClassSetFieldSlotClassRow) -> ClassColumns<'_> {
    match class {
        ClassSetFieldSlotClassRow::Workspace {
            declaration_id,
            fq_name,
            rel_path,
        } => ClassColumns {
            kind: "workspace",
            declaration_id: Some(declaration_id),
            fq_name,
            rel_path: Some(rel_path),
            symbol_id: None,
        },
        ClassSetFieldSlotClassRow::External { fq_name, symbol_id } => ClassColumns {
            kind: "external",
            declaration_id: None,
            fq_name,
            rel_path: None,
            symbol_id: Some(symbol_id),
        },
    }
}

fn semantic_work_values(work: SemanticWork) -> [usize; 16] {
    [
        work.source_bytes,
        work.procedures,
        work.blocks,
        work.program_points,
        work.values,
        work.allocations,
        work.call_sites,
        work.memory_locations,
        work.captures,
        work.source_mappings,
        work.evidence,
        work.gaps,
        work.events,
        work.control_edges,
        work.nested_entries,
        work.owned_text_bytes,
    ]
}

fn semantic_work_from_values(values: &[i64]) -> Result<SemanticWork> {
    let mut converted = [0usize; 16];
    if values.len() != converted.len() {
        return Err(StoreError::corrupt(
            "class-set field-slot work shape is corrupt",
        ));
    }
    for (target, value) in converted.iter_mut().zip(values) {
        *target = usize::try_from(*value)
            .map_err(|_| StoreError::corrupt("class-set field-slot work value is invalid"))?;
    }
    Ok(SemanticWork {
        source_bytes: converted[0],
        procedures: converted[1],
        blocks: converted[2],
        program_points: converted[3],
        values: converted[4],
        allocations: converted[5],
        call_sites: converted[6],
        memory_locations: converted[7],
        captures: converted[8],
        source_mappings: converted[9],
        evidence: converted[10],
        gaps: converted[11],
        events: converted[12],
        control_edges: converted[13],
        nested_entries: converted[14],
        owned_text_bytes: converted[15],
    })
}

fn bounded_count(value: i64, max: usize, name: &str) -> Result<usize> {
    let value = usize::try_from(value).map_err(|_| {
        StoreError::corrupt(format!("class-set field-slot {name} count is invalid"))
    })?;
    if value > max {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot {name} count exceeds {max}"
        )));
    }
    Ok(value)
}

fn bool_value(value: i64, name: &str) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::corrupt(format!(
            "class-set field-slot {name} is invalid"
        ))),
    }
}

fn admit_text_bytes(total: &mut usize, row_bytes: i64) -> Result<()> {
    let row_bytes = bounded_count(
        row_bytes,
        MAX_FIELD_SLOT_TEXT_BYTES,
        "payload row text byte",
    )?;
    *total = total.checked_add(row_bytes).ok_or_else(|| {
        StoreError::resource_bound("class-set field-slot payload text size overflows usize")
    })?;
    if *total > MAX_FIELD_SLOT_TEXT_BYTES {
        return Err(StoreError::resource_bound(format!(
            "class-set field-slot payload text exceeds {MAX_FIELD_SLOT_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn dense_index(value: i64, len: usize, name: &str) -> Result<usize> {
    let value = usize::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("class-set field-slot {name} is invalid")))?;
    if value >= len {
        return Err(StoreError::corrupt(format!(
            "class-set field-slot {name} is out of range"
        )));
    }
    Ok(value)
}

fn u32_value(value: i64, name: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("class-set field-slot {name} exceeds u32")))
}

fn digest(bytes: Vec<u8>, name: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StoreError::corrupt(format!(
            "class-set field-slot {name} digest has {} bytes",
            bytes.len()
        ))
    })
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(StoreError::new(
            "class-set field-slot publication cancelled",
        ))
    } else {
        Ok(())
    }
}

fn ensure_optional_cancellation(cancellation: Option<&CancellationToken>) -> Result<()> {
    match cancellation {
        Some(cancellation) => ensure_not_cancelled(cancellation),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::StoreErrorKind;
    use crate::analyzer::store::planner_statistics::tests::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use std::sync::{Arc, Barrier};

    fn key() -> ClassSetFieldSlotIndexKey {
        ClassSetFieldSlotIndexKey {
            language: Language::Python,
            workspace_content_digest: [1; 32],
            provider_behavior_digest: [2; 32],
            active_pack_digest: [3; 32],
            adapter_semantics_digest: [4; 32],
            representation_version: 1,
        }
    }

    fn row() -> ClassSetFieldSlotIndexRow {
        ClassSetFieldSlotIndexRow::try_new(
            key(),
            vec![ClassSetFieldSlotRow {
                owner: ClassSetFieldSlotClassRow::Workspace {
                    declaration_id: "decl:v1:owner".to_string(),
                    fq_name: "sample.Owner".to_string(),
                    rel_path: "sample.py".to_string(),
                },
                member: "value".to_string(),
                atoms: vec![
                    ClassSetFieldSlotAtomRow {
                        value: ClassSetFieldSlotAtomValueRow::Class(
                            ClassSetFieldSlotClassRow::External {
                                fq_name: "builtins.str".to_string(),
                                symbol_id: "python:builtins:str".to_string(),
                            },
                        ),
                        source: ClassSetFieldSlotSourceRow {
                            rel_path: "sample.py".to_string(),
                            start_byte: 12,
                            start_line: 0,
                            start_byte_column: 12,
                            end_byte: 18,
                            end_line: 0,
                            end_byte_column: 18,
                            kind: "literal".to_string(),
                        },
                    },
                    ClassSetFieldSlotAtomRow {
                        value: ClassSetFieldSlotAtomValueRow::Unknown(
                            "open_type_bound".to_string(),
                        ),
                        source: ClassSetFieldSlotSourceRow {
                            rel_path: "sample.py".to_string(),
                            start_byte: 20,
                            start_line: 1,
                            start_byte_column: 0,
                            end_byte: 24,
                            end_line: 1,
                            end_byte_column: 4,
                            kind: "unknown".to_string(),
                        },
                    },
                    ClassSetFieldSlotAtomRow {
                        value: ClassSetFieldSlotAtomValueRow::Unknown(
                            "scalar_receiver".to_string(),
                        ),
                        source: ClassSetFieldSlotSourceRow {
                            rel_path: "sample.py".to_string(),
                            start_byte: 25,
                            start_line: 1,
                            start_byte_column: 5,
                            end_byte: 29,
                            end_line: 1,
                            end_byte_column: 9,
                            kind: "literal".to_string(),
                        },
                    },
                ],
            }],
            vec![ClassSetFieldSlotArtifactRow {
                rel_path: "samplé.py".to_string(),
                public_digest: [5; 32],
                work: SemanticWork {
                    procedures: 2,
                    ..SemanticWork::default()
                },
            }],
            ClassSetFieldStoreSurveyRow::default(),
        )
        .unwrap()
    }

    fn load(
        store: &AnalyzerStore,
        key: &ClassSetFieldSlotIndexKey,
    ) -> Result<Option<ClassSetFieldSlotIndexRow>> {
        store.class_set_field_slot_index(key, &CancellationToken::new())
    }

    fn reconstruct(row: ClassSetFieldSlotIndexRow) -> Result<ClassSetFieldSlotIndexRow> {
        ClassSetFieldSlotIndexRow::try_new(row.key, row.slots, row.artifacts, row.store_survey)
    }

    fn row_for(language: Language, seed: u8) -> ClassSetFieldSlotIndexRow {
        let mut value = row();
        value.key.language = language;
        value.key.workspace_content_digest = [seed; 32];
        reconstruct(value).unwrap()
    }

    fn table_counts(store: &AnalyzerStore) -> [i64; 5] {
        let conn = store.read_conn().unwrap();
        [
            "class_set_field_slot_indexes",
            "class_set_field_slot_artifacts",
            "class_set_field_slots",
            "class_set_field_slot_atoms",
            "class_set_field_slot_stores",
        ]
        .map(|table| {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
        })
    }

    #[test]
    fn field_slot_dto_rejects_noncanonical_and_nonportable_evidence() {
        let mut candidate = row();
        candidate.slots.push(candidate.slots[0].clone());
        assert!(
            reconstruct(candidate).is_err(),
            "duplicate slots are not canonical"
        );

        let mut candidate = row();
        candidate.slots[0].atoms.reverse();
        assert!(reconstruct(candidate).is_err(), "atom order is canonical");

        let mut candidate = row();
        candidate.artifacts.push(candidate.artifacts[0].clone());
        assert!(
            reconstruct(candidate).is_err(),
            "artifact paths are unique and ordered"
        );

        let mut candidate = row();
        let ClassSetFieldSlotClassRow::Workspace { rel_path, .. } = &mut candidate.slots[0].owner
        else {
            panic!("fixture owner is workspace-local");
        };
        *rel_path = "/tmp/owner.py".to_string();
        assert!(
            reconstruct(candidate).is_err(),
            "workspace classes cannot escape the mount"
        );

        let mut candidate = row();
        candidate.slots[0].atoms[0].source.rel_path = "../sample.py".to_string();
        assert!(
            reconstruct(candidate).is_err(),
            "source paths cannot contain parent components"
        );

        let mut candidate = row();
        candidate.artifacts[0].rel_path = "src/./sample.py".to_string();
        assert!(
            reconstruct(candidate).is_err(),
            "artifact paths must already be canonical"
        );

        let mut candidate = row();
        candidate.slots[0].atoms[0].source.end_byte = 11;
        assert!(
            reconstruct(candidate).is_err(),
            "source spans cannot end before they start"
        );

        let mut candidate = row();
        candidate.slots[0].atoms[0].source.kind = "future_source_kind".to_string();
        assert!(
            reconstruct(candidate).is_err(),
            "source kinds use the persisted vocabulary"
        );

        let mut candidate = row();
        candidate.slots[0].atoms[1].value =
            ClassSetFieldSlotAtomValueRow::Unknown("future_reason".to_string());
        assert!(
            reconstruct(candidate).is_err(),
            "unknown reasons use the persisted vocabulary"
        );
    }

    #[test]
    fn persisted_field_slots_bound_headers_digests_and_child_cardinality() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = row();
        store
            .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
            .unwrap();

        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_field_slot_indexes SET slot_count=?1",
                params![i64::try_from(MAX_FIELD_SLOTS).unwrap() + 1],
            )
            .unwrap();
        let error = load(&store, &expected.key).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::ResourceBound);
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap(),
            "a bounded corrupt header is replaced transactionally"
        );

        store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON;
                 UPDATE class_set_field_slot_indexes SET content_digest=zeroblob(31);
                 PRAGMA ignore_check_constraints=OFF;",
            )
            .unwrap();
        let error = load(&store, &expected.key).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::Corrupt);
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );

        store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON;
                 UPDATE class_set_field_slot_artifacts
                 SET artifact_public_digest=zeroblob(31);
                 PRAGMA ignore_check_constraints=OFF;",
            )
            .unwrap();
        let error = load(&store, &expected.key).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::Corrupt);
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );

        let index_id = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT index_id FROM class_set_field_slot_indexes",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO class_set_field_slots VALUES(
                   ?1,1,'external',NULL,'sample.Extra',NULL,'python:sample:extra','extra')",
                params![index_id],
            )
            .unwrap();
        let error = load(&store, &expected.key).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::Corrupt);
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap(),
            "an extra child is removed through the parent cascade"
        );
        assert_eq!(load(&store, &expected.key).unwrap(), Some(expected));
        assert_eq!(table_counts(&store), [1, 1, 1, 3, 0]);
    }

    #[test]
    fn operational_store_errors_do_not_trigger_corruption_repair() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = row();
        store
            .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute("DROP TABLE class_set_field_slot_artifacts", [])
            .unwrap();

        let error = load(&store, &expected.key).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::Generic);
        let error = store
            .publish_class_set_field_slot_index(expected, &CancellationToken::new())
            .unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::Generic);
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM class_set_field_slot_indexes",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            1,
            "an operational failure must not delete the existing parent"
        );
    }

    #[test]
    fn cancellation_rolls_back_a_partially_inserted_field_slot_index() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut template = row();
        template.slots[0].atoms = (0..100)
            .map(|ordinal| ClassSetFieldSlotAtomRow {
                value: ClassSetFieldSlotAtomValueRow::Unknown("field_slot_incomplete".to_string()),
                source: ClassSetFieldSlotSourceRow {
                    rel_path: "sample.py".to_string(),
                    start_byte: ordinal,
                    start_line: ordinal,
                    start_byte_column: 0,
                    end_byte: ordinal + 1,
                    end_line: ordinal,
                    end_byte_column: 1,
                    kind: "unknown".to_string(),
                },
            })
            .collect();
        let expected = reconstruct(template).unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(211);

        assert!(
            store
                .publish_class_set_field_slot_index(expected, &cancellation)
                .is_err()
        );
        assert!(cancellation.is_cancelled());
        assert_eq!(
            table_counts(&store),
            [0, 0, 0, 0, 0],
            "the immediate transaction exposes none of its partial children"
        );
    }

    #[test]
    fn idempotent_publication_does_not_touch_headers_or_children() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = row();
        store
            .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_field_slot_indexes SET published_at=123456789",
                [],
            )
            .unwrap();
        let before = table_counts(&store);

        assert!(
            !store
                .publish_class_set_field_slot_index(expected, &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(table_counts(&store), before);
        let published_at = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT published_at FROM class_set_field_slot_indexes",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(published_at, 123456789);
    }

    #[test]
    fn retention_is_recent_eight_per_language_and_cascades_children() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        for seed in 1..=10 {
            for language in [Language::Python, Language::Ruby] {
                store
                    .publish_class_set_field_slot_index(
                        row_for(language, seed),
                        &CancellationToken::new(),
                    )
                    .unwrap();
            }
        }

        let conn = store.conn.lock().unwrap();
        for language in [Language::Python, Language::Ruby] {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM class_set_field_slot_indexes WHERE lang=?1",
                    params![language.config_label()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                8
            );
        }
        drop(conn);
        assert_eq!(
            table_counts(&store),
            [16, 16, 16, 48, 0],
            "pruned parents remove every normalized child row"
        );
        for language in [Language::Python, Language::Ruby] {
            assert!(load(&store, &row_for(language, 1).key).unwrap().is_none());
            assert!(load(&store, &row_for(language, 2).key).unwrap().is_none());
            assert!(load(&store, &row_for(language, 10).key).unwrap().is_some());
        }
    }

    #[test]
    fn concurrent_same_key_publications_expose_one_complete_index() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("field-slots.db");
        let first_store = AnalyzerStore::open_persistent(&path).unwrap();
        let second_store = AnalyzerStore::open_persistent(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let expected = row();
        let first_row = expected.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_store
                .publish_class_set_field_slot_index(first_row, &CancellationToken::new())
                .unwrap()
        });
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        });
        let mut publications = [first.join().unwrap(), second.join().unwrap()];
        publications.sort_unstable();
        assert_eq!(publications, [false, true]);

        let store = AnalyzerStore::open_persistent(&path).unwrap();
        assert_eq!(load(&store, &key()).unwrap(), Some(row()));
        assert_eq!(table_counts(&store), [1, 1, 1, 3, 0]);
    }

    #[test]
    fn divergent_same_key_publication_fails_closed_with_compact_differences() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let existing = row();
        assert!(
            store
                .publish_class_set_field_slot_index(existing.clone(), &CancellationToken::new())
                .unwrap()
        );

        let mut candidate = existing.clone();
        candidate.artifacts[0].public_digest = [6; 32];
        candidate.artifacts[0].work.procedures += 1;
        candidate.slots[0].member = "other".to_string();
        let candidate = reconstruct(candidate).unwrap();
        let error = store
            .publish_class_set_field_slot_index(candidate.clone(), &CancellationToken::new())
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "existing_digest={}",
                StableDigest::from_array(*existing.content_digest())
            )),
            "{message}"
        );
        assert!(
            message.contains(&format!(
                "candidate_digest={}",
                StableDigest::from_array(*candidate.content_digest())
            )),
            "{message}"
        );
        for difference in [
            "artifact_identities_differ=true",
            "artifact_work_differ=true",
            "slots_differ=true",
        ] {
            assert!(message.contains(difference), "{message}");
        }
        assert_eq!(load(&store, &existing.key).unwrap(), Some(existing));
        assert_eq!(table_counts(&store), [1, 1, 1, 3, 0]);
    }

    #[test]
    fn exact_field_slot_index_round_trips_and_is_idempotent() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = row();
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert!(
            !store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(load(&store, &key()).unwrap(), Some(expected));

        let old_key = key();
        let mut replacement_key = key();
        replacement_key.workspace_content_digest = [9; 32];
        let replacement = ClassSetFieldSlotIndexRow::try_new(
            replacement_key.clone(),
            row().slots,
            row().artifacts,
            ClassSetFieldStoreSurveyRow::default(),
        )
        .unwrap();
        assert!(
            store
                .publish_class_set_field_slot_index(replacement.clone(), &CancellationToken::new())
                .unwrap()
        );
        let mut latest = (replacement_key, replacement);
        for seed in 10..18 {
            let mut next_key = key();
            next_key.workspace_content_digest = [seed; 32];
            let next = ClassSetFieldSlotIndexRow::try_new(
                next_key.clone(),
                row().slots,
                row().artifacts,
                ClassSetFieldStoreSurveyRow::default(),
            )
            .unwrap();
            store
                .publish_class_set_field_slot_index(next.clone(), &CancellationToken::new())
                .unwrap();
            latest = (next_key, next);
        }
        assert!(load(&store, &old_key).unwrap().is_none());
        assert_eq!(load(&store, &latest.0).unwrap(), Some(latest.1));
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM class_set_field_slot_indexes WHERE lang='python'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            8
        );
    }

    #[test]
    fn field_store_survey_round_trips_owned_and_unattributed_writes() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = ClassSetFieldSlotIndexRow::try_new(
            key(),
            Vec::new(),
            Vec::new(),
            ClassSetFieldStoreSurveyRow {
                stores: vec![
                    ClassSetFieldStoreRow {
                        owner: None,
                        member: "value".to_string(),
                    },
                    ClassSetFieldStoreRow {
                        owner: Some(ClassSetFieldSlotClassRow::Workspace {
                            declaration_id: "decl:v1:owner".to_string(),
                            fq_name: "sample.Owner".to_string(),
                            rel_path: "sample.py".to_string(),
                        }),
                        member: "value".to_string(),
                    },
                ],
                unknown_members: true,
            },
        )
        .unwrap();
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(load(&store, &key()).unwrap(), Some(expected));
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT store_survey_count, store_survey_unknown_members
                 FROM class_set_field_slot_indexes",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
            (2, 1)
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM class_set_field_slot_stores WHERE owner_kind IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn field_store_survey_corrupt_count_and_payload_are_repaired() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let expected = ClassSetFieldSlotIndexRow::try_new(
            key(),
            Vec::new(),
            Vec::new(),
            ClassSetFieldStoreSurveyRow {
                stores: vec![ClassSetFieldStoreRow {
                    owner: None,
                    member: "value".to_string(),
                }],
                unknown_members: true,
            },
        )
        .unwrap();
        store
            .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_field_slot_indexes SET store_survey_count=?1",
                params![i64::try_from(MAX_FIELD_SLOT_STORES).unwrap() + 1],
            )
            .unwrap();
        assert_eq!(
            load(&store, &key()).unwrap_err().kind(),
            StoreErrorKind::ResourceBound
        );
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );

        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_field_slot_indexes SET payload_text_bytes=payload_text_bytes+1",
                [],
            )
            .unwrap();
        assert_eq!(
            load(&store, &key()).unwrap_err().kind(),
            StoreErrorKind::Corrupt
        );
        assert!(
            store
                .publish_class_set_field_slot_index(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(load(&store, &key()).unwrap(), Some(expected));
    }

    #[test]
    fn field_slot_index_fails_closed_on_cancellation_and_corruption() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            store
                .publish_class_set_field_slot_index(row(), &cancelled)
                .is_err()
        );
        assert!(load(&store, &key()).unwrap().is_none());

        store
            .publish_class_set_field_slot_index(row(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_field_slot_indexes SET atom_count=atom_count+1",
                [],
            )
            .unwrap();
        assert!(load(&store, &key()).is_err());
        let replacement = row();
        assert!(
            store
                .publish_class_set_field_slot_index(replacement.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(load(&store, &key()).unwrap(), Some(replacement));
    }

    #[test]
    fn field_slot_queries_seek_persisted_indexes() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            state.install(&conn);
            for (name, expected) in [
                (
                    "class_set_field_slot_index",
                    "sqlite_autoindex_class_set_field_slot_indexes_1",
                ),
                (
                    "class_set_field_slots",
                    "sqlite_autoindex_class_set_field_slots_1",
                ),
                (
                    "class_set_field_slot_stores",
                    "sqlite_autoindex_class_set_field_slot_stores_1",
                ),
                (
                    "class_set_field_slot_atoms",
                    "sqlite_autoindex_class_set_field_slot_atoms_1",
                ),
                (
                    "class_set_field_slot_artifacts",
                    "sqlite_autoindex_class_set_field_slot_artifacts_1",
                ),
                (
                    "prune_old_class_set_field_slot_indexes",
                    "class_set_field_slot_indexes_recent",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|detail| detail.contains(expected)),
                    "{state} {name}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("AUTOMATIC")
                            && !detail.contains("TEMP B-TREE")
                            && !detail.contains("SCAN ")
                    }),
                    "{state} {name}: {plan:#?}"
                );
            }
        }
    }
}
