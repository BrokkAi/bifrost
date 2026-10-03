//! Atomic bounded persistence for immutable resolution bundles.
//!
//! A bundle is one content-owned interior: lexical paths, lookup recipes,
//! typed transfer facts, and declared root routes. Its rows use
//! descriptor-sorted storage-local keys and never contain mounted runtime
//! identities, selected package identities, workspace paths, or revision
//! context.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Mutex};

use moka::sync::Cache;
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{
    Connection, OptionalExtension, ToSql, Transaction, TransactionBehavior, params,
    params_from_iter,
};

use brokk_bifrost_core::analyzer::{Language, canonical_hash::CanonicalHasher};

use crate::CancellationToken;
use crate::hash::HashMap;
#[cfg(test)]
use crate::hash::HashSet;

use crate::analyzer::resolution::{SharedNameId, SharedNameInterner};

use super::resolution_manifest;
use super::resolution_prepare::{resolution_rows, typed_rows};
use super::{AnalyzerStore, Result, StoreError, usize_to_i64};

pub(crate) const NODE_CATALOG_PAYLOAD_BY_KEY_SQL: &str =
    "SELECT kind,semantic_local_key,semantic_shared_identity,target_local_key,target_boundary_key
     FROM resolution_node_catalog WHERE blob_id=?1 AND local_key=?2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PreparedResolutionValue {
    Null,
    Integer(i64),
    Text(String),
    Digest([u8; 32]),
}

impl Ord for PreparedResolutionValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let rank = |value: &Self| match value {
            Self::Null => 0,
            Self::Integer(_) => 1,
            Self::Text(_) => 2,
            Self::Digest(_) => 3,
        };
        rank(self)
            .cmp(&rank(other))
            .then_with(|| match (self, other) {
                (Self::Null, Self::Null) => Ordering::Equal,
                (Self::Integer(left), Self::Integer(right)) => left.cmp(right),
                (Self::Text(left), Self::Text(right)) => left.cmp(right),
                (Self::Digest(left), Self::Digest(right)) => left.cmp(right),
                _ => Ordering::Equal,
            })
    }
}

impl PartialOrd for PreparedResolutionValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ToSql for PreparedResolutionValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            Self::Null => ToSqlOutput::Borrowed(ValueRef::Null),
            Self::Integer(value) => ToSqlOutput::Borrowed(ValueRef::Integer(*value)),
            Self::Text(value) => ToSqlOutput::Borrowed(ValueRef::Text(value.as_bytes())),
            Self::Digest(value) => ToSqlOutput::Borrowed(ValueRef::Blob(value)),
        })
    }
}

impl PreparedResolutionValue {
    fn canonical_hash(&self, hasher: &mut CanonicalHasher) {
        match self {
            Self::Null => hasher.field("value", b"null"),
            Self::Integer(value) => {
                hasher.field("value_kind", b"integer");
                hasher.field("value", &value.to_be_bytes());
            }
            Self::Text(value) => {
                hasher.field("value_kind", b"text");
                hasher.field("value", value.as_bytes());
            }
            Self::Digest(value) => {
                hasher.field("value_kind", b"digest");
                hasher.field("value", value);
            }
        }
    }

    fn payload_bytes(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Digest(_) => 32,
            Self::Null | Self::Integer(_) => 0,
        }
    }
}

impl From<i64> for PreparedResolutionValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<u32> for PreparedResolutionValue {
    fn from(value: u32) -> Self {
        Self::Integer(i64::from(value))
    }
}

impl From<bool> for PreparedResolutionValue {
    fn from(value: bool) -> Self {
        Self::Integer(i64::from(value))
    }
}

impl From<String> for PreparedResolutionValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for PreparedResolutionValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<[u8; 32]> for PreparedResolutionValue {
    fn from(value: [u8; 32]) -> Self {
        Self::Digest(value)
    }
}

impl<T: Into<PreparedResolutionValue>> From<Option<T>> for PreparedResolutionValue {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PreparedResolutionRow {
    values: Box<[PreparedResolutionValue]>,
}

impl PreparedResolutionRow {
    pub(super) fn new(values: impl Into<Box<[PreparedResolutionValue]>>) -> Self {
        Self {
            values: values.into(),
        }
    }

    fn canonical_digest(&self, cancellation: &CancellationToken) -> Option<[u8; 32]> {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-persisted-row:v1");
        hasher.field(
            "field_count",
            &u64::try_from(self.values.len())
                .expect("usize fits u64 on supported targets")
                .to_be_bytes(),
        );
        for value in &self.values {
            if cancellation.is_cancelled() {
                return None;
            }
            value.canonical_hash(&mut hasher);
        }
        Some(hasher.finish())
    }

    fn payload_bytes(&self, cancellation: &CancellationToken) -> Option<usize> {
        let mut total = 0usize;
        for value in &self.values {
            if cancellation.is_cancelled() {
                return None;
            }
            total = total.saturating_add(value.payload_bytes());
        }
        Some(total)
    }
}

#[derive(Clone, Copy)]
struct ResolutionFamilySpec {
    name: &'static str,
    table: &'static str,
    columns: &'static str,
    arity: usize,
    key_arity: usize,
}

/// Which typed relation one membership row records, and which one a typed read
/// asks for.
///
/// Every typed read that resolves its mounts from an interned identity asks a
/// question of the shape "which blobs hold a fact of this relation under this
/// identity". The relation is that question, not a mode: a type transfer
/// indexed by its source slot and the same transfer indexed by its target slot
/// are two questions, and a blob answers one without answering the other. The
/// three qualified-route reads that consult one interior index share one
/// relation because they ask one question.
///
/// The discriminant is persisted in `resolution_typed_fact_lookups.relation`,
/// so renumbering a variant changes every interior digest and rotates the
/// bundle epochs with the rest of the family.
macro_rules! typed_fact_relations {
    ($($variant:ident = $code:literal,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(i64)]
        pub(super) enum TypedFactRelation {
            $($variant = $code,)*
        }

        impl TypedFactRelation {
            /// Every relation, in discriminant order. The pins walk it, so a
            /// variant added here is measured without being listed twice.
            pub(super) const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// How many there are, as an array length.
            pub(super) const COUNT: usize = Self::ALL.len();

            pub(super) const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)*
                }
            }
        }
    };
}

typed_fact_relations! {
    RustReferenceContext = 0,
    RustDeclarationAuthority = 1,
    TypedFrontierSlot = 2,
    TypeIdentityObservationReference = 3,
    TypeFrontierCompletionFrontier = 4,
    TypeTransferSourceSlot = 5,
    TypeTransferTargetSlot = 6,
    IntrinsicSeedSlot = 7,
    IntrinsicSeedTypeIdentity = 8,
    BindingProjectionReference = 9,
    BindingProjectionOutputSlot = 10,
    QualifiedRouteReference = 11,
    QualifiedRouteQualifierSlot = 12,
    QualifiedRouteLookup = 13,
    QualifiedRouteGapReason = 14,
    DeclarationTypeDefinition = 15,
    DeclarationTypeSlot = 16,
    DeclarationVisibilityDefinition = 17,
    MemberScopeDefinition = 18,
    MemberOwnerDefinition = 19,
    MemberOwnerOwnerDefinition = 20,
    DeferredMemberOwnerDefinition = 21,
    DeferredMemberOwnerLookup = 22,
    ConstructionRequirementDefinition = 23,
    SupertypeDefinition = 24,
    SupertypeReference = 25,
    SupertypeFrontier = 26,
    DefinitionPropertyGapDefinition = 27,
    CallApplicabilityCalleeReference = 28,
    CallApplicabilityGapReason = 29,
    CallableSignatureDefinition = 30,
    GapReasonProvenanceReason = 31,
    DefinitionPropertyGapReason = 32,
    TypeComponentContainer = 33,
    UnderlyingTypeDefinition = 34,
}

impl TypedFactRelation {
    /// The integer the family stores and every statement predicates on.
    pub(super) const fn code(self) -> i64 {
        self as i64
    }
}

// Keep the storage family, manifest count column, and count-array order in one
// declaration. Consumers use the generated names instead of positional
// constants so adding a family cannot silently shift a reader's meaning.
macro_rules! resolution_bundle_families {
    ($macro:ident) => {
        $macro! {
            rust_reference_contexts => ("rust_reference_contexts", "resolution_rust_reference_contexts", "expected_rust_reference_context_count", "semantic_key, source_site, source_occurrence, module_context, module_declaration, cfg_condition", 6, 1),
            rust_declaration_authorities => ("rust_declaration_authorities", "resolution_rust_declaration_authorities", "expected_rust_declaration_authority_count", "semantic_key, source_site, declaration, visibility, module_context, module_declaration, cfg_condition, activation_reason", 8, 1),
            semantic_catalog => ("semantic_catalog", "resolution_semantic_catalog", "expected_semantic_catalog_count", "local_key, identity_digest, shared_identity, import_source_site, import_start_byte, import_end_byte, import_route_kind", 7, 1),
            node_catalog => ("node_catalog", "resolution_node_catalog", "expected_node_catalog_count", "local_key, identity_digest, source_scope, kind, semantic_local_key, semantic_shared_identity, target_local_key, target_boundary_key", 8, 1),
            package_references => ("package_references", "resolution_package_references", "expected_package_reference_count", "token_key, domain_key, reference_key, source_site, root_scope_key, namespace, lookup_key", 7, 1),
            package_members => ("package_members", "resolution_package_members", "expected_package_member_count", "token_key, definition_key, domain_key, source_site, root_scope_key, namespace, lookup_key", 7, 2),
            go_package_imports => ("go_package_imports", "resolution_go_package_imports", "expected_go_package_import_count", "definition_key, source_site, file_scope_key, spelling_choice_key, start_byte, end_byte, kind", 7, 1),
            contract_references => ("contract_references", "resolution_contract_references", "expected_contract_reference_count", "definition, member_kind, position, reference_site", 4, 3),
            path_endpoint_headers => ("path_endpoint_headers", "resolution_path_endpoint_headers", "expected_path_endpoint_header_count", "direction, identity_id, symbol_fixed_count, open_tail", 4, 4),
            path_terminal_headers => ("path_terminal_headers", "resolution_path_terminal_headers", "expected_path_terminal_header_count", "direction, identity_id, symbol_fixed_count", 3, 3),
            reference_lookup_identities => ("reference_lookup_identities", "resolution_reference_lookup_identities", "expected_reference_lookup_identity_count", "semantic_key, identity_id", 2, 1),
            root_route_segments => ("root_route_segments", "resolution_root_route_segments", "expected_root_route_segment_count", "path_key, position, segment, terminal_spelling, reference_source_site, reference_start_byte, reference_end_byte", 7, 2),
            semantic_sites => ("semantic_sites", "resolution_semantic_sites", "expected_semantic_site_count", "source_site, namespace, semantic_role, semantic_key", 4, 1),
            additional_definition_namespaces => ("additional_definition_namespaces", "resolution_additional_definition_namespaces", "expected_additional_definition_namespace_count", "definition_semantic_key, namespace, hoisting", 3, 2),
            definition_unit_crosswalks => ("definition_unit_crosswalks", "resolution_definition_unit_crosswalks", "expected_definition_unit_crosswalk_count", "definition_semantic_key, unit_key, identity_digest", 3, 1),
            declaration_visibility_properties => ("declaration_visibility_properties", "resolution_declaration_visibility_properties", "expected_declaration_visibility_property_count", "definition_semantic_key, visibility", 2, 1),
            member_scope_properties => ("member_scope_properties", "resolution_member_scope_properties", "expected_member_scope_property_count", "definition_semantic_key, scope_head_node_key", 2, 1),
            member_owner_properties => ("member_owner_properties", "resolution_member_owner_properties", "expected_member_owner_property_count", "definition_semantic_key, owner_definition_semantic_key, owner_scope_head_node_key, member_kind, member_access, qualifier_compatibility", 6, 6),
            trait_implementations => ("trait_implementations", "resolution_trait_implementations", "expected_trait_implementation_count", "relation_key, side, position, segment, terminal_spelling, impl_site, impl_start_byte, impl_end_byte", 8, 3),
            typed_fact_lookups => ("typed_fact_lookups", "resolution_typed_fact_lookups", "expected_typed_fact_lookup_count", "relation, identity_id", 2, 2),
        }
    };
}

macro_rules! define_bundle_rows {
    ($($field:ident => ($name:literal, $table:literal, $count_column:literal, $columns:literal, $arity:literal, $key_arity:literal),)*) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub(crate) struct PreparedResolutionBundleRows {
            $(pub(super) $field: Vec<PreparedResolutionRow>,)*
        }

        impl PreparedResolutionBundleRows {
            fn family_specs() -> [ResolutionFamilySpec; ResolutionManifestFamilyIndex::FamilyCount as usize] {
                [$(ResolutionFamilySpec {
                    name: $name,
                    table: $table,
                    columns: $columns,
                    arity: $arity,
                    key_arity: $key_arity,
                },)*]
            }

            fn families(&self) -> [&[PreparedResolutionRow]; ResolutionManifestFamilyIndex::FamilyCount as usize] {
                [$(&self.$field,)*]
            }

            fn families_mut(
                &mut self,
            ) -> [&mut Vec<PreparedResolutionRow>; ResolutionManifestFamilyIndex::FamilyCount as usize] {
                [$(&mut self.$field,)*]
            }
        }
    };
}

resolution_bundle_families!(define_bundle_rows);

macro_rules! define_manifest_counts {
    ($($field:ident => ($name:literal, $table:literal, $count_column:literal, $columns:literal, $arity:literal, $key_arity:literal),)*) => {
        pub(super) const RESOLUTION_MANIFEST_COUNT_COLUMNS: &[&str] = &{
            let header_count = ResolutionManifestFamilyIndex::FamilyCount as usize;
            let mut columns = [""; ResolutionManifestFamilyIndex::FamilyCount as usize
                + resolution_manifest::BODY_MANIFEST_COLUMNS.len()];
            $(columns[ResolutionManifestFamilyIndex::$field as usize] = $count_column;)*
            let mut index = 0;
            while index < resolution_manifest::BODY_MANIFEST_COLUMNS.len() {
                columns[header_count + index] = resolution_manifest::BODY_MANIFEST_COLUMNS[index];
                index += 1;
            }
            columns
        };

        #[allow(non_camel_case_types)]
        #[repr(usize)]
        #[derive(Clone, Copy)]
        enum ResolutionManifestFamilyIndex {
            $($field,)*
            FamilyCount,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct ResolutionManifestCounts(
            [u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
        );

        impl ResolutionManifestCounts {
            pub(crate) const fn from_array(
                counts: [u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
            ) -> Self {
                Self(counts)
            }

            pub(crate) const fn get(&self, family_index: usize) -> u64 {
                self.0[family_index]
            }

            pub(crate) const fn values(&self) -> &[u64] {
                &self.0
            }

        }
    };
}

resolution_bundle_families!(define_manifest_counts);

// Expose the count questions selected readers actually ask; family order is
// owned solely by the descriptor above, not by this reader API inventory.
macro_rules! manifest_count_accessors {
    ($($field:ident),* $(,)?) => {
        impl ResolutionManifestCounts {
            $(pub(crate) const fn $field(&self) -> u64 {
                self.get(ResolutionManifestFamilyIndex::$field as usize)
            })*
        }
    };
}

manifest_count_accessors!(
    path_endpoint_headers,
    semantic_sites,
    member_scope_properties,
);
impl PreparedResolutionBundleRows {
    fn canonicalize(&mut self, cancellation: &CancellationToken) -> bool {
        for (spec, rows) in Self::family_specs().into_iter().zip(self.families_mut()) {
            if cancellation.is_cancelled() {
                return false;
            }
            for row in rows.iter() {
                if cancellation.is_cancelled() {
                    return false;
                }
                assert_eq!(row.values.len(), spec.arity, "{} row arity", spec.name);
            }
            let Some(canonical) = cancellable_sort_by(
                std::mem::take(rows),
                |left, right| prepared_row_order(left, right, spec.key_arity),
                cancellation,
            ) else {
                return false;
            };
            *rows = canonical;
            for pair in rows.windows(2) {
                if cancellation.is_cancelled() {
                    return false;
                }
                assert_ne!(
                    pair[0].values[..spec.key_arity],
                    pair[1].values[..spec.key_arity],
                    "{} rows repeat a SQL primary key",
                    spec.name
                );
            }
        }
        true
    }

    fn counts(&self) -> [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()] {
        let mut counts = [0; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
        for (index, rows) in self.families().into_iter().enumerate() {
            counts[index] = rows.len();
        }
        counts
    }

    fn canonical_digest(
        &self,
        semantic_language: Language,
        producer_epoch: &str,
        family_counts: &[usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
        cancellation: &CancellationToken,
    ) -> Option<[u8; 32]> {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-persisted-bundle:v1");
        hasher.field(
            "semantic_language",
            semantic_language.config_label().as_bytes(),
        );
        hasher.field("producer_epoch", producer_epoch.as_bytes());
        for ((spec, rows), row_count) in Self::family_specs()
            .into_iter()
            .zip(self.families())
            .zip(family_counts)
        {
            if cancellation.is_cancelled() {
                return None;
            }
            debug_assert_eq!(*row_count, rows.len());
            hasher.field("family_name", spec.name.as_bytes());
            hasher.field(
                "family_row_count",
                &u64::try_from(*row_count)
                    .expect("usize fits u64 on supported targets")
                    .to_be_bytes(),
            );
            for row in rows {
                if cancellation.is_cancelled() {
                    return None;
                }
                hasher.field("row", &row.canonical_digest(cancellation)?);
            }
        }
        Some(hasher.finish())
    }

    fn payload_bytes(
        &self,
        semantic_language: Language,
        producer_epoch: &str,
        cancellation: &CancellationToken,
    ) -> Option<usize> {
        let mut total = semantic_language
            .config_label()
            .len()
            .saturating_add(producer_epoch.len())
            .saturating_add(32);
        for rows in self.families() {
            if cancellation.is_cancelled() {
                return None;
            }
            for row in rows {
                total = total.saturating_add(row.payload_bytes(cancellation)?);
            }
        }
        Some(total)
    }
}

pub(super) fn cancellable_sort_by<T>(
    rows: Vec<T>,
    compare: impl Fn(&T, &T) -> Ordering,
    cancellation: &CancellationToken,
) -> Option<Vec<T>> {
    let len = rows.len();
    if cancellation.is_cancelled() {
        return None;
    }
    let mut source = Vec::with_capacity(len);
    let mut destination = Vec::with_capacity(len);
    for row in rows {
        if cancellation.is_cancelled() {
            return None;
        }
        source.push(Some(row));
        destination.push(None);
    }
    let mut width = 1usize;
    while width < len {
        let mut start = 0usize;
        while start < len {
            let middle = start.saturating_add(width).min(len);
            let end = middle.saturating_add(width).min(len);
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle || right < end {
                if cancellation.is_cancelled() {
                    return None;
                }
                let take_left = right >= end
                    || (left < middle
                        && compare(
                            source[left].as_ref().expect("unmerged left row"),
                            source[right].as_ref().expect("unmerged right row"),
                        )
                        .is_le());
                let selected = if take_left {
                    let selected = left;
                    left += 1;
                    selected
                } else {
                    let selected = right;
                    right += 1;
                    selected
                };
                destination[output] = source[selected].take();
                output += 1;
            }
            start = end;
        }
        std::mem::swap(&mut source, &mut destination);
        width = width.saturating_mul(2);
    }
    let mut sorted = Vec::with_capacity(len);
    for row in source {
        if cancellation.is_cancelled() {
            return None;
        }
        sorted.push(row.expect("final merge populated every row"));
    }
    Some(sorted)
}

fn prepared_row_order(
    left: &PreparedResolutionRow,
    right: &PreparedResolutionRow,
    key_arity: usize,
) -> Ordering {
    left.values[..key_arity]
        .cmp(&right.values[..key_arity])
        .then_with(|| left.cmp(right))
}

/// Every resolution table a store may hold, in schema-name order.
///
/// Tier 2 is computed on demand and never written, so this list is both the
/// schema inventory and the read surface: a production statement that opens a
/// resolution table outside it is reading something the writer stopped
/// producing. Two pins hold it, one over the live schema and one over the
/// statement registry.
pub(super) const PERSISTED_RESOLUTION_TABLES: &[&str] = &[
    "resolution_additional_definition_namespaces",
    // Milestone 6 port block 4 (lane TF): the typed facts, one table per fact
    // type, written by the tier-1 writer at index time and read by the typed
    // reader. Milestone 7 moves the write to first demand and this list moves
    // with it.
    "resolution_binding_projections",
    "resolution_call_obligations",
    "resolution_callable_parameter_owners",
    "resolution_callable_signatures",
    "resolution_capsule_declarations",
    "resolution_capsule_inputs",
    "resolution_capsule_reference_contexts",
    "resolution_construction_requirements",
    "resolution_contract_references",
    "resolution_declaration_types",
    "resolution_deferred_member_owners",
    "resolution_definition_property_gaps",
    "resolution_definition_unit_crosswalks",
    // Publication authority, the workspace-wide shared identity table and the
    // per-language producer epoch.
    "resolution_fragment_interiors",
    // Milestone 6, port block 3 (lane GR): one row per lowering coverage gap
    // and one per distinct reason, written at index time as the candidate gap
    // headers they replace were.
    "resolution_gap_reasons",
    "resolution_gaps",
    "resolution_go_package_imports",
    "resolution_identities",
    "resolution_intrinsic_seed_identities",
    "resolution_intrinsic_seeds",
    "resolution_member_owner_properties",
    "resolution_member_scope_properties",
    "resolution_node_catalog",
    "resolution_package_members",
    "resolution_package_references",
    "resolution_path_endpoint_headers",
    "resolution_path_terminal_headers",
    // Milestone 6's checkpoint (lane PK) writes a blob's partial paths at index
    // time so that the point benchmark's store is built cold by the binary
    // under test. It is written by the tier-1 writer and read by a tier-1
    // reader, so it belongs in this list; milestone 7 moves the write to first
    // demand and the list moves with it.
    "resolution_paths",
    "resolution_producer_epochs",
    "resolution_qualified_routes",
    "resolution_reference_lookup_identities",
    "resolution_root_route_segments",
    "resolution_rust_declaration_authorities",
    "resolution_rust_reference_contexts",
    "resolution_semantic_catalog",
    "resolution_semantic_sites",
    // Port block 2 (lane CM), written beside the path rows at index time for
    // the same reason: the reader is a tier-1 reader and the benchmark's store
    // is built cold by the binary under test.
    "resolution_sites",
    "resolution_supertypes",
    "resolution_trait_implementations",
    "resolution_type_components",
    "resolution_type_frontiers",
    "resolution_type_transfers",
    "resolution_typed_fact_lookups",
    "resolution_underlying_types",
];

/// One sole producer-identity bump point for the complete persisted bundle.
pub(crate) const fn resolution_bundle_epoch(language: Language) -> &'static str {
    match language {
        Language::Java => "resolution-bundle-java-v28",
        Language::Go => "resolution-bundle-go-v33",
        Language::Cpp => "resolution-bundle-cpp-v19",
        Language::JavaScript => "resolution-bundle-javascript-v18",
        Language::TypeScript => "resolution-bundle-typescript-v18",
        Language::Python => "resolution-bundle-python-v18",
        Language::Rust => "resolution-bundle-rust-v95",
        Language::Php => "resolution-bundle-php-v18",
        Language::Scala => "resolution-bundle-scala-v18",
        Language::CSharp => "resolution-bundle-csharp-v18",
        Language::Ruby => "resolution-bundle-ruby-v18",
        Language::Kotlin => "resolution-bundle-kotlin-v18",
        Language::None => panic!("a resolution bundle needs an analyzable language"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedResolutionBundle {
    semantic_language: Language,
    producer_epoch: &'static str,
    interior_digest: [u8; 32],
    family_counts: [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
    logical_rows: usize,
    payload_bytes: usize,
    rows: PreparedResolutionBundleRows,
    // Complete producer families retain shared-name slots until the transaction
    // interns them. Their canonical digest hashes producer digests, never slots.
    path_rows: resolution_rows::PreparedPathRows,
    site_rows: Vec<resolution_rows::PreparedSiteRow>,
    typed_fact_rows: typed_rows::PreparedTypedRows,
    recipe_rows: Vec<resolution_rows::PreparedLookupRecipeRow>,
    gap_rows: resolution_rows::PreparedGapRows,
    shared_name_digests: Vec<[u8; 32]>,
}

impl PreparedResolutionBundle {
    pub(super) fn set_capsule_manifest(
        &mut self,
        digest: [u8; 32],
        declarations: usize,
        references: usize,
        presentation_payload_bytes: usize,
    ) {
        let count = self.family_counts.len();
        self.family_counts[count - 3..].copy_from_slice(&[1, declarations, references]);
        self.logical_rows = self.family_counts.iter().copied().sum::<usize>() + 1;
        self.interior_digest = digest;
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(presentation_payload_bytes);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        semantic_language: Language,
        mut rows: PreparedResolutionBundleRows,
        path_rows: resolution_rows::PreparedPathRows,
        site_rows: Vec<resolution_rows::PreparedSiteRow>,
        typed_fact_rows: typed_rows::PreparedTypedRows,
        recipe_rows: Vec<resolution_rows::PreparedLookupRecipeRow>,
        gap_rows: resolution_rows::PreparedGapRows,
        shared_name_digests: Vec<[u8; 32]>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        assert_ne!(semantic_language, Language::None);
        if !rows.canonicalize(cancellation) {
            return None;
        }
        let producer_epoch = resolution_bundle_epoch(semantic_language);
        let mut family_counts = rows.counts();
        let headers_digest = rows.canonical_digest(
            semantic_language,
            producer_epoch,
            &family_counts,
            cancellation,
        )?;
        let interior_digest = resolution_manifest::complete_body_digest(
            headers_digest,
            &path_rows,
            &site_rows,
            &typed_fact_rows,
            &gap_rows,
            &recipe_rows,
            &shared_name_digests,
            cancellation,
        )?;
        family_counts[ResolutionManifestFamilyIndex::FamilyCount as usize..].copy_from_slice(
            &resolution_manifest::body_counts(&path_rows, &site_rows, &typed_fact_rows, &gap_rows),
        );
        let logical_rows = family_counts
            .into_iter()
            .fold(1usize, usize::saturating_add);
        let payload_bytes = rows
            .payload_bytes(semantic_language, producer_epoch, cancellation)?
            .saturating_add(resolution_manifest::estimated_body_payload_bytes(
                &path_rows,
                &typed_fact_rows,
                cancellation,
            )?);
        Some(Self {
            semantic_language,
            producer_epoch,
            interior_digest,
            family_counts,
            logical_rows,
            payload_bytes,
            rows,
            path_rows,
            site_rows,
            typed_fact_rows,
            recipe_rows,
            gap_rows,
            shared_name_digests,
        })
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    pub(crate) const fn producer_epoch(&self) -> &'static str {
        self.producer_epoch
    }

    pub(crate) const fn interior_digest(&self) -> [u8; 32] {
        self.interior_digest
    }

    pub(crate) const fn logical_rows(&self) -> usize {
        self.logical_rows
    }

    /// Pre-write batching estimate; committed witnesses carry measured SQLite
    /// payload bytes after interning and JSONB encoding.
    pub(crate) const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// The generic membership family's rows, as (relation, identity digest).
    ///
    /// The pin that proves a relation names exactly the blobs whose interior
    /// answers it compares this against the interior's own reads.
    #[cfg(test)]
    pub(super) fn typed_fact_lookups(&self) -> Vec<(i64, [u8; 32])> {
        self.rows
            .typed_fact_lookups
            .iter()
            .map(|row| {
                let PreparedResolutionValue::Integer(relation) = row.values[0] else {
                    panic!("a typed fact lookup names an integer relation");
                };
                let PreparedResolutionValue::Digest(digest) = row.values[1] else {
                    panic!("a typed fact lookup names an identity digest");
                };
                (relation, digest)
            })
            .collect()
    }

    pub(super) fn declaration_visibility_storage_cost(
        &self,
        cancellation: &CancellationToken,
    ) -> Option<(usize, usize)> {
        let rows = &self.rows.declaration_visibility_properties;
        let bytes = rows.iter().try_fold(0usize, |total, row| {
            Some(total.saturating_add(row.payload_bytes(cancellation)?))
        })?;
        Some((rows.len(), bytes))
    }

    #[cfg(test)]
    pub(super) fn family_counts(&self) -> [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()] {
        self.family_counts
    }
}

impl AnalyzerStore {
    /// Install the code-owned complete-bundle epoch for one storage language.
    /// Dialect storage keys (for example `typescript:tsx` and `cpp:c`) retain
    /// their own active row while sharing the semantic producer implementation.
    pub(crate) fn ensure_resolution_producer_epoch(
        &self,
        storage_language: &str,
        semantic_language: Language,
    ) -> Result<bool> {
        assert!(!storage_language.is_empty());
        let storage_language = storage_language.to_owned();
        let producer_epoch = resolution_bundle_epoch(semantic_language);
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous = tx
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = ?1",
                    [&storage_language],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if previous.as_deref() == Some(producer_epoch) {
                tx.commit()?;
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO resolution_producer_epochs(lang, producer_epoch)
                 VALUES(?1, ?2)
                 ON CONFLICT(lang) DO UPDATE SET producer_epoch = excluded.producer_epoch",
                params![storage_language, producer_epoch],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }
}

const RESOLUTION_SQLITE_PROGRESS_QUANTUM: i32 = 1_000;

#[derive(Default)]
struct ResolutionReadCancellationDispatcher {
    next_registration: u64,
    registrations: Vec<ResolutionReadCancellationRegistration>,
}

struct ResolutionReadCancellationRegistration {
    identity: u64,
    cancellation: CancellationToken,
}

impl ResolutionReadCancellationDispatcher {
    fn register(&mut self, cancellation: &CancellationToken) -> u64 {
        if self
            .registrations
            .iter()
            .any(|registration| registration.cancellation.is_cancelled())
        {
            cancellation.cancel();
        }
        let identity = self.next_registration;
        self.next_registration = self
            .next_registration
            .checked_add(1)
            .expect("resolution read cancellation registration identity overflowed");
        self.registrations
            .push(ResolutionReadCancellationRegistration {
                identity,
                cancellation: cancellation.clone(),
            });
        identity
    }

    fn unregister(&mut self, identity: u64) -> bool {
        let registration = self
            .registrations
            .pop()
            .expect("each resolution read cancellation registration is removed once");
        assert_eq!(
            registration.identity, identity,
            "resolution read cancellation registrations must leave in lexical order"
        );
        self.registrations.is_empty()
    }

    fn propagate_cancellation(&mut self) -> bool {
        let mut inherited_cancellation = false;
        for registration in &self.registrations {
            if inherited_cancellation {
                registration.cancellation.cancel();
            } else if registration.cancellation.is_cancelled() {
                inherited_cancellation = true;
            }
        }
        inherited_cancellation
    }
}

thread_local! {
    static RESOLUTION_READ_CANCELLATION_DISPATCHERS:
        RefCell<HashMap<usize, Arc<Mutex<ResolutionReadCancellationDispatcher>>>> =
        RefCell::new(HashMap::default());
}

struct ResolutionReadCancellationGuard<'connection> {
    connection: &'connection Connection,
    connection_identity: usize,
    dispatcher: Arc<Mutex<ResolutionReadCancellationDispatcher>>,
    registration: u64,
}

impl<'connection> ResolutionReadCancellationGuard<'connection> {
    fn install(
        connection: &'connection Connection,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let connection_identity = std::ptr::from_ref(connection).addr();
        let (dispatcher, install_handler) =
            RESOLUTION_READ_CANCELLATION_DISPATCHERS.with(|dispatchers| {
                let mut dispatchers = dispatchers.borrow_mut();
                if let Some(dispatcher) = dispatchers.get(&connection_identity) {
                    (Arc::clone(dispatcher), false)
                } else {
                    let dispatcher =
                        Arc::new(Mutex::new(ResolutionReadCancellationDispatcher::default()));
                    assert!(
                        dispatchers
                            .insert(connection_identity, Arc::clone(&dispatcher))
                            .is_none()
                    );
                    (dispatcher, true)
                }
            });
        let registration = dispatcher
            .lock()
            .expect("resolution read cancellation dispatcher lock is not poisoned")
            .register(cancellation);
        if install_handler {
            let callback_dispatcher = Arc::clone(&dispatcher);
            if let Err(error) = connection.progress_handler(
                RESOLUTION_SQLITE_PROGRESS_QUANTUM,
                Some(move || {
                    callback_dispatcher
                        .lock()
                        .expect("resolution read cancellation dispatcher lock is not poisoned")
                        .propagate_cancellation()
                }),
            ) {
                assert!(
                    dispatcher
                        .lock()
                        .expect("resolution read cancellation dispatcher lock is not poisoned")
                        .unregister(registration)
                );
                RESOLUTION_READ_CANCELLATION_DISPATCHERS.with(|dispatchers| {
                    let removed = dispatchers
                        .borrow_mut()
                        .remove(&connection_identity)
                        .expect("failed read handler installation owns its dispatcher");
                    assert!(Arc::ptr_eq(&removed, &dispatcher));
                });
                return Err(error.into());
            }
        }
        Ok(Self {
            connection,
            connection_identity,
            dispatcher,
            registration,
        })
    }

    fn clear(self) -> Result<()> {
        let remove_dispatcher = self
            .dispatcher
            .lock()
            .expect("resolution read cancellation dispatcher lock is not poisoned")
            .unregister(self.registration);
        if !remove_dispatcher {
            return Ok(());
        }
        let cleanup = self.connection.progress_handler(0, None::<fn() -> bool>);
        RESOLUTION_READ_CANCELLATION_DISPATCHERS.with(|dispatchers| {
            let removed = dispatchers
                .borrow_mut()
                .remove(&self.connection_identity)
                .expect("outer resolution read handler owns its dispatcher");
            assert!(Arc::ptr_eq(&removed, &self.dispatcher));
        });
        cleanup.map_err(Into::into)
    }
}

pub(super) fn with_resolution_progress_handler<T>(
    conn: &mut Connection,
    cancellation: &CancellationToken,
    job: impl FnOnce(&mut Connection) -> Result<T>,
) -> Result<T> {
    let callback_cancellation = cancellation.clone();
    conn.progress_handler(
        RESOLUTION_SQLITE_PROGRESS_QUANTUM,
        Some(move || callback_cancellation.is_cancelled()),
    )?;
    let result = catch_unwind(AssertUnwindSafe(|| job(conn)));
    let cleanup = conn.progress_handler(0, None::<fn() -> bool>);
    match result {
        Ok(result) => {
            cleanup?;
            result
        }
        Err(payload) => {
            cleanup.expect("resolution SQLite progress handler must clear during unwinding");
            resume_unwind(payload)
        }
    }
}

/// Run one read-only resolution statement group with connection-local SQLite
/// cancellation installed for exactly the duration of `job`.
///
/// Nested reads on the same retained connection share one SQLite callback and
/// register their tokens in lexical order. Cancellation propagates from an
/// active parent to its descendants, never in the opposite direction.
/// Selected readers still release the handler before invoking a visitor so a
/// callback cannot retain statement-local borrows across another selected read.
pub(super) fn with_resolution_read_progress_handler<T>(
    conn: &Connection,
    cancellation: &CancellationToken,
    job: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    let guard = ResolutionReadCancellationGuard::install(conn, cancellation)?;
    let result = catch_unwind(AssertUnwindSafe(|| job(conn)));
    let cleanup = guard.clear();
    match result {
        Ok(result) => {
            cleanup?;
            result
        }
        Err(payload) => {
            cleanup.expect("resolution SQLite progress handler must clear during unwinding");
            resume_unwind(payload)
        }
    }
}

pub(super) fn require_active_resolution_epoch(
    conn: &Connection,
    storage_language: &str,
    expected_epoch: &str,
) -> Result<()> {
    let active_epoch = conn
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = ?1",
            [storage_language],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if active_epoch.as_deref() != Some(expected_epoch) {
        return Err(StoreError::stale_resolution(format!(
            "stale resolution producer epoch for {storage_language}: prepared {expected_epoch:?}, active {active_epoch:?}"
        )));
    }
    Ok(())
}

pub(super) fn insert_prepared_bundle_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    storage_language: &str,
    bundle: &PreparedResolutionBundle,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let count_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS.join(", ");
    let value_count = 5 + RESOLUTION_MANIFEST_COUNT_COLUMNS.len() + 2;
    let placeholders = (1..=value_count)
        .map(|position| format!("?{position}"))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest_sql = format!(
        "INSERT INTO resolution_fragment_interiors(
           blob_id, lang, semantic_language, producer_epoch, interior_digest,
           {count_columns}, logical_rows, payload_bytes, publication_state
         ) VALUES({placeholders}, 'building')"
    );
    let mut manifest_values = Vec::with_capacity(value_count);
    manifest_values.push(PreparedResolutionValue::Integer(blob_id));
    manifest_values.push(storage_language.into());
    manifest_values.push(bundle.semantic_language.config_label().into());
    manifest_values.push(bundle.producer_epoch.into());
    manifest_values.push(bundle.interior_digest.into());
    for count in bundle.family_counts {
        manifest_values.push(PreparedResolutionValue::Integer(usize_to_i64(count)?));
    }
    manifest_values.push(PreparedResolutionValue::Integer(usize_to_i64(
        bundle.logical_rows,
    )?));
    manifest_values.push(PreparedResolutionValue::Integer(usize_to_i64(
        bundle.payload_bytes,
    )?));
    assert_eq!(manifest_values.len(), value_count);
    tx.execute(&manifest_sql, params_from_iter(&manifest_values))?;

    for (spec, rows) in PreparedResolutionBundleRows::family_specs()
        .into_iter()
        .zip(bundle.rows.families())
    {
        if let Some(digest_column) = interned_identity_column(spec.name) {
            if !insert_interned_header_family(tx, blob_id, spec, digest_column, rows, cancellation)?
            {
                return Ok(false);
            }
            continue;
        }
        if !insert_resolution_family(tx, blob_id, spec, rows, cancellation)? {
            return Ok(false);
        }
    }
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    if !insert_row_families(tx, blob_id, bundle, cancellation)? {
        return Ok(false);
    }
    if !insert_gap_rows(tx, blob_id, bundle, cancellation)? {
        return Ok(false);
    }
    if !insert_typed_fact_rows(tx, blob_id, bundle, cancellation)? {
        return Ok(false);
    }
    let payload_bytes = tx
        .prepare_cached(resolution_manifest::COMPLETE_PUBLICATION_COST_SQL)?
        .query_row([blob_id], |row| {
            for (index, expected) in bundle.family_counts.iter().enumerate() {
                let actual: usize = row.get(index)?;
                assert_eq!(
                    actual, *expected,
                    "complete resolution family {}",
                    RESOLUTION_MANIFEST_COUNT_COLUMNS[index]
                );
            }
            row.get::<_, i64>(RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
        })?;
    tx.execute(
        "UPDATE resolution_fragment_interiors SET payload_bytes = ?2 WHERE blob_id = ?1",
        params![blob_id, payload_bytes],
    )?;
    #[cfg(debug_assertions)]
    {
        let publication_state: String = tx.query_row(
            "SELECT publication_state FROM resolution_fragment_interiors WHERE blob_id = ?1",
            [blob_id],
            |row| row.get(0),
        )?;
        debug_assert_eq!(publication_state, "building");
    }
    let sealed = tx.execute(
        "UPDATE resolution_fragment_interiors
         SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )?;
    debug_assert_eq!(sealed, 1);
    Ok(true)
}

/// Write the blob's `resolution_paths` and `resolution_sites` rows and fill
/// the recipe columns of every shared lookup identity it interns (milestone
/// 6's checkpoint, lane PK; the sites are port block 2, lane CM).
///
/// Interning is what makes this a write-time job rather than a preparation
/// job: a shared name's id is a store fact, so the prepared body carries slots
/// and this renders them once the ids exist. Every recipe is interned before
/// any path is written, because a path body may name a recipe the identity
/// table has not seen and the foreign key on the lead columns is immediate.
///
/// Index time is the checkpoint's placement, not the design's: milestone 7
/// moves it to first demand.
fn insert_row_families(
    tx: &Transaction<'_>,
    blob_id: i64,
    bundle: &PreparedResolutionBundle,
    cancellation: &CancellationToken,
) -> Result<bool> {
    // Every shared name of the blob's catalog, not only the ones a header
    // family or a path body names. An interior produced for this blob later
    // asserts that each of its shared ids is one of these rows.
    for digest in &bundle.shared_name_digests {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_identities(identity_digest) VALUES(?1)
             ON CONFLICT(identity_digest) DO NOTHING",
        )?
        .execute([digest.as_slice()])?;
    }
    for recipe in &bundle.recipe_rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        // One statement, no read: a name's recipe is the same wherever it is
        // seen, so the first blob that interns it fills the columns and every
        // later blob's write is a no-op the `WHERE` clause drops. Tract has
        // 484,527 recipe entries over 183 interiors and 22,206 distinct shared
        // names, so an unconditional UPDATE would be twenty-two writes per
        // name that change nothing.
        tx.prepare_cached(
            "INSERT INTO resolution_identities(
               identity_digest, semantic_language, namespace, spelling
             ) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(identity_digest) DO UPDATE
               SET semantic_language = excluded.semantic_language,
                   namespace = excluded.namespace,
                   spelling = excluded.spelling
               WHERE resolution_identities.semantic_language IS NULL",
        )?
        .execute(rusqlite::params![
            recipe.identity_digest.as_slice(),
            recipe.semantic_language,
            recipe.namespace,
            recipe.spelling,
        ])?;
    }
    let mut shared_ids = Vec::with_capacity(bundle.path_rows.shared.len());
    for digest in &bundle.path_rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        shared_ids.push(intern_resolution_identity(tx, digest)?);
    }
    let mut sites = tx.prepare_cached(
        "INSERT INTO resolution_sites(
           blob_id, site, role, namespace, site_kind, start_byte, end_byte,
           unqualified, owner, receiver_origin, go_spelling_namespace, go_definition_namespaces, go_package_qualifier
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    for row in &bundle.site_rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        sites.execute(rusqlite::params![
            blob_id,
            row.site,
            row.role,
            row.namespace,
            row.site_kind,
            row.start_byte,
            row.end_byte,
            row.unqualified,
            row.owner,
            row.receiver_origin,
            row.go_spelling_namespace,
            row.go_definition_namespaces,
            row.go_package_qualifier,
        ])?;
    }
    let mut statement = tx.prepare_cached(
        "INSERT INTO resolution_paths(
           blob_id, path, start_node, start_lead_local, start_lead_identity,
           start_lead_scoped, end_node, end_lead_local, end_lead_identity,
           end_lead_scoped, root_terminal, body, end_fixed_key, end_open_tail
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, jsonb(?12), ?13, ?14)",
    )?;
    let shared_id = |slot: Option<u32>| {
        slot.map(|slot| shared_ids[usize::try_from(slot).expect("a slot fits usize")])
    };
    for row in &bundle.path_rows.rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let root = row.root_endpoint.as_ref().map(|endpoint| {
            let mut key = resolution_rows::RootKeyBuilder::default();
            for &(symbol, scoped) in &endpoint.symbols {
                match symbol {
                    resolution_rows::PathBodyToken::Int(local) => {
                        key.push(Some(local), None, scoped)
                    }
                    resolution_rows::PathBodyToken::Shared(slot) => {
                        key.push(None, shared_id(Some(slot)), scoped)
                    }
                    other => unreachable!("a root symbol is an identity, not {other:?}"),
                }
            }
            (key.finish().0, i64::from(endpoint.open_tail))
        });
        debug_assert_eq!(root.is_some(), row.end_node == -1);
        statement.execute(rusqlite::params![
            blob_id,
            row.path,
            row.start_node,
            row.start_lead_local,
            shared_id(row.start_lead_shared),
            i64::from(row.start_lead_scoped),
            row.end_node,
            row.end_lead_local,
            shared_id(row.end_lead_shared),
            i64::from(row.end_lead_scoped),
            shared_id(row.root_terminal),
            resolution_rows::render_path_body(&row.body, &shared_ids),
            root.as_ref().map(|(key, _)| key),
            root.as_ref().map(|(_, tail)| *tail),
        ])?;
    }
    Ok(true)
}

/// Write the blob's `resolution_gaps` and `resolution_gap_reasons` rows
/// (milestone 6, port block 3, lane GR).
///
/// One row per lowering coverage gap and one per distinct reason. The lookup
/// a candidate branch is keyed on is a shared name, so it is interned here for
/// the same reason a path body's symbols are: the id is a store fact the
/// per-blob producer cannot know. `0` is the stored "every lookup".
///
/// Index time is the placement the candidate gap headers already had, so the
/// unconditional read still answers without opening a blob; milestone 7 moves
/// the rest of a blob's gaps to first demand.
fn insert_gap_rows(
    tx: &Transaction<'_>,
    blob_id: i64,
    bundle: &PreparedResolutionBundle,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let mut lookup_ids = Vec::with_capacity(bundle.gap_rows.shared.len());
    for digest in &bundle.gap_rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        lookup_ids.push(intern_resolution_identity(tx, digest)?);
    }
    let mut reasons = tx.prepare_cached(
        "INSERT INTO resolution_gap_reasons(blob_id, reason, site, origin)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for row in &bundle.gap_rows.reasons {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        reasons.execute(rusqlite::params![blob_id, row.reason, row.site, row.origin])?;
    }
    let mut gaps = tx.prepare_cached(
        "INSERT INTO resolution_gaps(blob_id, covers, subject, lookup, gap, reason)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for row in &bundle.gap_rows.rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let lookup = row.lookup.map_or(0, |slot| {
            lookup_ids[usize::try_from(slot).expect("a slot fits usize")]
        });
        gaps.execute(rusqlite::params![
            blob_id,
            row.covers,
            row.subject,
            lookup,
            row.gap,
            row.reason,
        ])?;
    }
    Ok(true)
}

/// Write the blob's typed-fact rows (milestone 6 port block 4, lane TF).
///
/// Every shared name a typed row names is interned first, for the same reason
/// the path rows intern theirs: the foreign key on a lookup column is
/// immediate, and a name's id is a store fact the per-blob producer cannot
/// know. `insert_path_rows` has already interned the blob's whole catalog, so
/// these lookups find their ids without inserting anything; the call is kept
/// because the two row sets are independent of each other's placement.
///
/// Index time is the checkpoint's placement, not the design's: milestone 7
/// moves it to first demand with everything else.
fn insert_typed_fact_rows(
    tx: &Transaction<'_>,
    blob_id: i64,
    bundle: &PreparedResolutionBundle,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let rows = &bundle.typed_fact_rows;
    let mut shared_ids = Vec::with_capacity(rows.shared.len());
    for digest in &rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        shared_ids.push(intern_resolution_identity(tx, digest)?);
    }
    let shared_id = |slot: u32| shared_ids[usize::try_from(slot).expect("a slot fits usize")];
    let body = |tokens: &[resolution_rows::PathBodyToken]| {
        resolution_rows::render_path_body(tokens, &shared_ids)
    };
    let optional_body = |tokens: &Option<Vec<resolution_rows::PathBodyToken>>| {
        tokens.as_ref().map(|tokens| body(tokens))
    };

    for row in &rows.type_frontiers {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_type_frontiers(blob_id, slot, role, identity_reference)
             VALUES(?1, ?2, ?3, ?4)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.slot,
            row.role,
            row.identity_reference
        ])?;
    }
    for row in &rows.type_transfers {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_type_transfers(
               blob_id, source_slot, rule, target_slot, kind, indirection_delta,
               reference_indirection_delta, value_transform, completion
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, jsonb(?9))",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.source_slot,
            row.rule,
            row.target_slot,
            row.kind,
            row.indirection_delta,
            row.reference_indirection_delta,
            row.value_transform,
            optional_body(&row.completion),
        ])?;
    }
    for row in &rows.type_components {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_type_components(
               blob_id, container_slot, constructor, kind, component_slot
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.container_slot,
            row.constructor,
            row.kind,
            row.component_slot,
        ])?;
    }
    for row in &rows.underlying_types {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_underlying_types(blob_id, definition, slot)
             VALUES(?1, ?2, ?3)",
        )?
        .execute(rusqlite::params![blob_id, row.definition, row.slot])?;
    }
    for row in &rows.intrinsic_seeds {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_intrinsic_seeds(
               blob_id, slot, kind, spelling, possible_values, completion
             ) VALUES(?1, ?2, ?3, ?4, jsonb(?5), jsonb(?6))",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.slot,
            row.kind,
            row.spelling,
            body(&row.possible_values),
            optional_body(&row.completion),
        ])?;
    }
    for row in &rows.intrinsic_seed_identities {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_intrinsic_seed_identities(blob_id, identity_id, slot)
             VALUES(?1, ?2, ?3)",
        )?
        .execute(rusqlite::params![
            blob_id,
            shared_id(row.identity),
            row.slot
        ])?;
    }
    for row in &rows.binding_projections {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_binding_projections(blob_id, reference, output_slot, kind)
             VALUES(?1, ?2, ?3, ?4)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.reference,
            row.output_slot,
            row.kind
        ])?;
    }
    for row in &rows.qualified_routes {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_qualified_routes(
               blob_id, reference, precedence_ordinal, qualifier_slot, lookup,
               source_lookup, namespace, projection_output_slot, projection_kind,
               coarse_gap_reason, open_member_surface
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.reference,
            row.precedence_ordinal,
            row.qualifier_slot,
            shared_id(row.lookup),
            shared_id(row.source_lookup),
            row.namespace,
            row.projection_output_slot,
            row.projection_kind,
            row.coarse_gap_reason,
            row.open_member_surface,
        ])?;
    }
    for row in &rows.declaration_types {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_declaration_types(blob_id, definition, role, slot)
             VALUES(?1, ?2, ?3, ?4)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.definition,
            row.role,
            row.slot
        ])?;
    }
    for row in &rows.deferred_member_owners {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_deferred_member_owners(blob_id, definition, seq, lookup, body)
             VALUES(?1, ?2, ?3, ?4, jsonb(?5))",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.definition,
            row.seq,
            shared_id(row.lookup),
            body(&row.body),
        ])?;
    }
    for row in &rows.construction_requirements {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_construction_requirements(
               blob_id, definition, required_owner_definition, kind
             ) VALUES(?1, ?2, ?3, ?4)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.definition,
            row.required_owner_definition,
            row.kind
        ])?;
    }
    for row in &rows.supertypes {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_supertypes(blob_id, definition, reference, frontier, kind)
             VALUES(?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.definition,
            row.reference,
            row.frontier,
            row.kind
        ])?;
    }
    for row in &rows.definition_property_gaps {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_definition_property_gaps(
               blob_id, definition, seq, kind, frontier, reason, site
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.definition,
            row.seq,
            row.kind,
            row.frontier,
            row.reason,
            row.site
        ])?;
    }
    for row in &rows.call_obligations {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_call_obligations(
               blob_id, callee_reference, call, receiver_slot, result_slot,
               explicit_type_argument_count, applicability_reason, argument_slots,
               type_argument_slots, eligible_rules, completion
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, jsonb(?8), jsonb(?9), jsonb(?10), jsonb(?11))",
        )?
        .execute(rusqlite::params![
            blob_id,
            row.callee_reference,
            row.call,
            row.receiver_slot,
            row.result_slot,
            row.explicit_type_argument_count,
            row.applicability_reason,
            body(&row.argument_slots),
            body(&row.type_argument_slots),
            body(&row.eligible_rules),
            optional_body(&row.completion),
        ])?;
    }
    for row in &rows.callable_parameter_owners {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_callable_parameter_owners(blob_id, parameter_definition, signature_definition)
             VALUES(?1, ?2, ?3)",
        )?.execute(rusqlite::params![blob_id, row.parameter_definition, row.signature_definition])?;
    }
    for row in &rows.callable_signatures {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tx.prepare_cached(
            "INSERT INTO resolution_callable_signatures(blob_id, definition, body)
             VALUES(?1, ?2, jsonb(?3))",
        )?
        .execute(rusqlite::params![blob_id, row.definition, body(&row.body)])?;
    }
    Ok(!cancellation.is_cancelled())
}

/// The tier-1 discovery families reference a shared identity by integer. The
/// prepared row carries the 32-byte digest, because interning is a store fact
/// that the per-blob producer cannot know; this names the column the writer
/// replaces with the interned id.
const fn interned_identity_column(family: &str) -> Option<usize> {
    match family.as_bytes() {
        b"path_endpoint_headers"
        | b"path_terminal_headers"
        | b"reference_lookup_identities"
        | b"typed_fact_lookups" => Some(1),
        b"semantic_catalog" => Some(2),
        b"node_catalog" => Some(5),
        _ => None,
    }
}

/// Intern one shared identity digest on the writer thread and return its id.
///
/// The identity table is workspace-wide and immutable: a digest keeps its id
/// for the life of the cache, so the insert is idempotent and the select that
/// follows is the authority.
fn intern_resolution_identity(tx: &Transaction<'_>, digest: &[u8; 32]) -> Result<i64> {
    tx.prepare_cached(
        "INSERT INTO resolution_identities(identity_digest) VALUES(?1)
         ON CONFLICT(identity_digest) DO NOTHING",
    )?
    .execute([digest.as_slice()])?;
    Ok(tx
        .prepare_cached("SELECT id FROM resolution_identities WHERE identity_digest = ?1")?
        .query_row([digest.as_slice()], |row| row.get::<_, i64>(0))?)
}

fn insert_interned_header_family(
    tx: &Transaction<'_>,
    blob_id: i64,
    spec: ResolutionFamilySpec,
    digest_column: usize,
    rows: &[PreparedResolutionRow],
    cancellation: &CancellationToken,
) -> Result<bool> {
    if rows.is_empty() {
        return Ok(!cancellation.is_cancelled());
    }
    let placeholders = (1..=spec.arity + 1)
        .map(|position| format!("?{position}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {}(blob_id, {}) VALUES({placeholders})",
        spec.table, spec.columns
    );
    let mut values = Vec::<PreparedResolutionValue>::with_capacity(spec.arity + 1);
    for row in rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        values.clear();
        values.push(PreparedResolutionValue::Integer(blob_id));
        for (position, value) in row.values.iter().enumerate() {
            if position != digest_column {
                values.push(value.clone());
                continue;
            }
            values.push(match value {
                PreparedResolutionValue::Digest(digest) => {
                    PreparedResolutionValue::Integer(intern_resolution_identity(tx, digest)?)
                }
                PreparedResolutionValue::Null => PreparedResolutionValue::Null,
                other => panic!("{} identity column holds {other:?}", spec.name),
            });
        }
        tx.prepare_cached(&sql)?
            .execute(params_from_iter(values.iter()))?;
    }
    Ok(true)
}

fn insert_resolution_family(
    tx: &Transaction<'_>,
    blob_id: i64,
    spec: ResolutionFamilySpec,
    rows: &[PreparedResolutionRow],
    cancellation: &CancellationToken,
) -> Result<bool> {
    if rows.is_empty() {
        return Ok(!cancellation.is_cancelled());
    }
    let placeholders = (1..=spec.arity + 1)
        .map(|position| {
            if matches!(
                (spec.name, position),
                ("rust_reference_contexts", 7) | ("rust_declaration_authorities", 5 | 8)
            ) {
                format!("jsonb(?{position})")
            } else {
                format!("?{position}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {}(blob_id, {}) VALUES({placeholders})",
        spec.table, spec.columns
    );
    let mut statement = tx.prepare_cached(&sql)?;
    let mut values = Vec::<&dyn ToSql>::with_capacity(spec.arity + 1);
    for row in rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        values.clear();
        values.push(&blob_id);
        values.extend(row.values.iter().map(|value| value as &dyn ToSql));
        statement.execute(values.as_slice())?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::resolution_prepare::ResolutionInteriorPreparation;
    use crate::analyzer::resolution::{BindingFragmentId, rich_java_resolution_facts_for_test};

    use super::*;

    fn shared_name_connection() -> Connection {
        let mut connection = crate::cache_db::open_in_memory_store_connection()
            .expect("shared-name store connection");
        crate::cache_db::configure_connection(&mut connection).expect("configure store");
        crate::cache_db::migrate(&mut connection).expect("migrate store");
        connection
    }

    fn commit_shared_names(
        connection: &mut Connection,
        digests: &[[u8; 32]],
    ) -> Vec<([u8; 32], SharedNameId)> {
        let tx = connection
            .transaction()
            .expect("identity publication transaction");
        let receipt = digests
            .iter()
            .map(|digest| {
                let stored =
                    intern_resolution_identity(&tx, digest).expect("intern committed name");
                (*digest, SharedNameId::interned(stored))
            })
            .collect();
        tx.commit().expect("commit identities before admission");
        receipt
    }

    #[test]
    fn shared_name_admission_preserves_first_ids_in_either_receipt_order() {
        for reversed in [false, true] {
            let mut connection = shared_name_connection();
            let cache = SharedNameCache::new();
            let table = SharedNameTable::new(cache.clone());
            let synthetic = table.interner(&connection).intern([99; 32]);
            let first = table.interner(&connection).intern([1; 32]);
            let second = table.interner(&connection).intern([2; 32]);
            assert_ne!(first, second);
            assert!(!first.is_interned());
            assert_eq!(table.interner(&connection).to_persisted(first), None);
            assert!(
                cache.entries.get(&[1; 32]).is_none(),
                "misses are request-owned"
            );

            // The third catalog member is absent from any endpoint header and
            // has never been interned by this request. Complete membership
            // includes it anyway, without retaining it in the request table.
            let receipt = commit_shared_names(&mut connection, &[[2; 32], [3; 32], [1; 32]]);
            let stored_first = receipt[2].1;
            let stored_second = receipt[0].1;
            let stored_unused = receipt[1].1;
            let mut admission = receipt.clone();
            if reversed {
                admission.reverse();
            }
            for _ in 0..2 {
                assert!(table.admit_persisted_names(&admission, &CancellationToken::new()));
                let names = table.interner(&connection);
                assert_eq!(names.intern([1; 32]), first);
                assert_eq!(names.intern([2; 32]), second);
                assert_eq!(names.from_persisted(stored_first), first);
                assert_eq!(names.from_persisted(stored_second), second);
                assert_eq!(names.to_persisted(first), Some(stored_first));
                assert_eq!(names.to_persisted(second), Some(stored_second));
                assert_eq!(names.to_persisted(synthetic), None);
                assert_eq!(names.from_persisted(stored_unused), stored_unused);
                assert!(!table.ids.borrow().contains_key(&[3; 32]));
            }
            assert_eq!(table.aliases.borrow().from_persisted.len(), 2);
            assert_eq!(table.aliases.borrow().to_persisted.len(), 2);
            assert_eq!(table.interner(&connection).intern([3; 32]), stored_unused);
            assert_eq!(table.aliases.borrow().from_persisted.len(), 2);

            // A new request sees stored IDs, even though the older request
            // continues using its original identities across crate stages.
            let next = SharedNameTable::new(cache.clone());
            assert_eq!(next.interner(&connection).intern([1; 32]), stored_first);
            assert_eq!(next.interner(&connection).intern([2; 32]), stored_second);
            assert_eq!(cache.entries.get(&[1; 32]), Some(stored_first));
            assert_eq!(cache.entries.get(&[2; 32]), Some(stored_second));
            assert_eq!(table.interner(&connection).intern([1; 32]), first);
            assert!(next.admit_persisted_names(&receipt, &CancellationToken::new()));
            assert!(next.aliases.borrow().from_persisted.is_empty());
            assert!(next.aliases.borrow().to_persisted.is_empty());

            // A fresh admission reader gets identical immutable membership.
            let cached = commit_shared_names(&mut connection, &[[2; 32], [3; 32], [1; 32]]);
            assert_eq!(cached, receipt);
            assert!(table.admit_persisted_names(&cached, &CancellationToken::new()));
            // Conversion is receipt-driven even when the attached connection
            // cannot possibly query the identity table.
            let no_schema = Connection::open_in_memory().expect("connection without store tables");
            let conversions = table.interner(&no_schema);
            assert_eq!(conversions.from_persisted(stored_first), first);
            assert_eq!(conversions.to_persisted(second), Some(stored_second));
            assert_eq!(conversions.to_persisted(synthetic), None);
            assert!(table.admit_persisted_names(&cached, &CancellationToken::new()));
            let count: i64 = connection
                .query_row("SELECT COUNT(*) FROM resolution_identities", [], |row| {
                    row.get(0)
                })
                .expect("identity count");
            assert_eq!(
                count, 3,
                "synthetic names and request misses are never published"
            );
        }
    }

    #[test]
    fn shared_name_admission_cancellation_keeps_both_directions_atomic() {
        let mut connection = shared_name_connection();
        for checks in 1..=4 {
            let table = SharedNameTable::new(SharedNameCache::new());
            let digests = [
                [checks as u8; 32],
                [checks as u8 + 10; 32],
                [checks as u8 + 20; 32],
            ];
            let requests = digests.map(|digest| table.interner(&connection).intern(digest));
            let receipt = commit_shared_names(&mut connection, &digests);
            // Preserve an earlier stage's successful admission on every abort.
            assert!(table.admit_persisted_names(&receipt[..1], &CancellationToken::new()));
            let before_decode = table.aliases.borrow().from_persisted.clone();
            let before_bind = table.aliases.borrow().to_persisted.clone();
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            assert!(!table.admit_persisted_names(&receipt, &cancellation));
            assert_eq!(table.aliases.borrow().from_persisted, before_decode);
            assert_eq!(table.aliases.borrow().to_persisted, before_bind);
            assert!(table.admit_persisted_names(&receipt, &CancellationToken::new()));
            for (request, (_, stored)) in requests.into_iter().zip(receipt) {
                assert_eq!(table.interner(&connection).from_persisted(stored), request);
                assert_eq!(
                    table.interner(&connection).to_persisted(request),
                    Some(stored)
                );
            }
        }
        let table = SharedNameTable::new(SharedNameCache::new());
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(!table.admit_persisted_names(&[], &cancelled));
        assert!(table.admit_persisted_names(&[], &CancellationToken::new()));
    }

    #[test]
    fn shared_name_admission_rejects_conflicts_before_installing_aliases() {
        let mut connection = shared_name_connection();
        let table = SharedNameTable::new(SharedNameCache::new());
        for digest in [[1; 32], [2; 32], [3; 32]] {
            table.interner(&connection).intern(digest);
        }
        let receipt = commit_shared_names(&mut connection, &[[1; 32], [2; 32], [3; 32]]);
        assert!(table.admit_persisted_names(&receipt[..1], &CancellationToken::new()));
        let before_decode = table.aliases.borrow().from_persisted.clone();
        let before_bind = table.aliases.borrow().to_persisted.clone();
        for invalid in [
            vec![receipt[1], ([2; 32], receipt[2].1)],
            vec![receipt[1], ([3; 32], receipt[1].1)],
            vec![receipt[1], ([1; 32], receipt[2].1)],
            vec![receipt[1], ([3; 32], receipt[0].1)],
            vec![receipt[1], ([3; 32], SharedNameId::per_request(8))],
        ] {
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    table.admit_persisted_names(&invalid, &CancellationToken::new())
                }))
                .is_err()
            );
            assert_eq!(table.aliases.borrow().from_persisted, before_decode);
            assert_eq!(table.aliases.borrow().to_persisted, before_bind);
        }
        assert!(table.admit_persisted_names(&receipt, &CancellationToken::new()));
    }

    fn namespace_row(key: i64, hoisting: &str) -> PreparedResolutionRow {
        PreparedResolutionRow::new(vec![key.into(), "value".into(), hoisting.into()])
    }

    fn sample_rows(extra_semantic: bool) -> PreparedResolutionBundleRows {
        let mut rows = PreparedResolutionBundleRows::default();
        rows.additional_definition_namespaces
            .push(namespace_row(0, "name1"));
        if extra_semantic {
            rows.additional_definition_namespaces
                .push(namespace_row(1, "name2"));
        }
        rows
    }

    fn bundle(language: Language, rows: PreparedResolutionBundleRows) -> PreparedResolutionBundle {
        PreparedResolutionBundle::new(
            language,
            rows,
            resolution_rows::PreparedPathRows::default(),
            Vec::new(),
            typed_rows::PreparedTypedRows::default(),
            Vec::new(),
            resolution_rows::PreparedGapRows::default(),
            Vec::new(),
            &CancellationToken::default(),
        )
        .expect("uncancelled bundle construction")
    }

    #[test]
    fn node_payload_changes_complete_digest_and_shared_prewrite_cost() {
        let rows = |semantic_local: Option<i64>, semantic_shared: Option<[u8; 32]>| {
            let mut rows = PreparedResolutionBundleRows::default();
            rows.node_catalog.push(PreparedResolutionRow::new(vec![
                3_i64.into(),
                [1; 32].into(),
                PreparedResolutionValue::Null,
                2_i64.into(),
                semantic_local.into(),
                semantic_shared.into(),
                PreparedResolutionValue::Null,
                PreparedResolutionValue::Null,
            ]));
            rows
        };
        let first = bundle(Language::Java, rows(Some(1), None));
        let second = bundle(Language::Java, rows(Some(2), None));
        let shared = bundle(Language::Java, rows(None, Some([7; 32])));
        let changed_shared = bundle(Language::Java, rows(None, Some([8; 32])));
        assert_ne!(first.interior_digest(), second.interior_digest());
        assert_ne!(shared.interior_digest(), changed_shared.interior_digest());
        assert_eq!(first.logical_rows(), shared.logical_rows());
        assert_eq!(
            shared.payload_bytes(),
            first.payload_bytes() + 32,
            "prewrite carries the producer digest until the writer assigns the scalar shared ID"
        );
        let mut reordered = rows(Some(1), None);
        let mut second_node = reordered.node_catalog[0].clone();
        second_node.values[0] = 4_i64.into();
        reordered.node_catalog.push(second_node);
        let before = bundle(Language::Java, reordered.clone());
        reordered.node_catalog.reverse();
        assert_eq!(before, bundle(Language::Java, reordered));
        let mut jump = rows(None, None);
        jump.node_catalog[0].values[3] = 7_i64.into();
        jump.node_catalog[0].values[6] = 1_i64.into();
        let local_target = bundle(Language::Java, jump.clone());
        jump.node_catalog[0].values[6] = PreparedResolutionValue::Null;
        jump.node_catalog[0].values[7] = 0_i64.into();
        assert_ne!(
            local_target.interior_digest(),
            bundle(Language::Java, jump).interior_digest()
        );
    }

    #[test]
    fn bundle_digest_is_order_independent_and_covers_every_named_header_family() {
        let first = bundle(Language::Java, sample_rows(true));
        let mut reordered_rows = sample_rows(true);
        reordered_rows.additional_definition_namespaces.reverse();
        let reordered = bundle(Language::Java, reordered_rows);
        let changed = bundle(Language::Java, sample_rows(false));
        let changed_language = bundle(Language::Cpp, sample_rows(true));

        assert_eq!(first.interior_digest, reordered.interior_digest);
        assert_ne!(first.interior_digest, changed.interior_digest);
        assert_ne!(first.interior_digest, changed_language.interior_digest);

        let empty = bundle(Language::Java, PreparedResolutionBundleRows::default());
        let mut family_digests = HashSet::default();
        for (family_index, spec) in PreparedResolutionBundleRows::family_specs()
            .into_iter()
            .enumerate()
        {
            let mut rows = PreparedResolutionBundleRows::default();
            rows.families_mut()[family_index].push(PreparedResolutionRow::new(
                (0..spec.arity)
                    .map(|_| PreparedResolutionValue::Integer(0))
                    .collect::<Vec<_>>(),
            ));
            let changed_family = bundle(Language::Java, rows);
            assert_ne!(
                changed_family.interior_digest, empty.interior_digest,
                "{} must participate in the bundle digest",
                spec.name
            );
            assert!(
                family_digests.insert(changed_family.interior_digest),
                "named family framing must distinguish {}",
                spec.name
            );
        }
        assert_eq!(
            family_digests.len(),
            ResolutionManifestFamilyIndex::FamilyCount as usize
        );
    }

    #[test]
    fn bundle_accounting_uses_all_text_and_digest_payloads() {
        let empty = bundle(Language::Java, PreparedResolutionBundleRows::default());
        assert_eq!(empty.logical_rows, 1);
        assert_eq!(
            empty.payload_bytes,
            Language::Java.config_label().len()
                + resolution_bundle_epoch(Language::Java).len()
                + 32
        );
        let populated = bundle(Language::Java, sample_rows(false));
        assert_eq!(populated.logical_rows, 2);
        assert_eq!(
            populated.payload_bytes,
            empty.payload_bytes + "value".len() + "name1".len()
        );
    }

    #[test]
    fn bundle_construction_polls_cancellation_during_canonicalization() {
        let mut rows = PreparedResolutionBundleRows::default();
        for key in 0..1_000 {
            rows.additional_definition_namespaces
                .push(namespace_row(key, "name1"));
        }
        let cancellation = CancellationToken::cancel_after_checks_for_test(20);
        assert!(
            PreparedResolutionBundle::new(
                Language::Java,
                rows,
                resolution_rows::PreparedPathRows::default(),
                Vec::new(),
                typed_rows::PreparedTypedRows::default(),
                Vec::new(),
                resolution_rows::PreparedGapRows::default(),
                Vec::new(),
                &cancellation,
            )
            .is_none()
        );
        assert!(cancellation.is_cancelled());
    }

    #[test]
    #[should_panic(expected = "additional_definition_namespaces rows repeat a SQL primary key")]
    fn bundle_rejects_repeated_sql_primary_keys() {
        let mut rows = sample_rows(false);
        rows.additional_definition_namespaces
            .push(namespace_row(0, "name2"));
        let _ = bundle(Language::Java, rows);
    }

    #[test]
    fn storage_aliases_keep_storage_outside_the_semantic_bundle() {
        let java = bundle(Language::Java, sample_rows(false));
        let cpp = bundle(Language::Cpp, sample_rows(false));
        assert_eq!(java.semantic_language(), Language::Java);
        assert_eq!(cpp.semantic_language(), Language::Cpp);
        assert_ne!(java.interior_digest, cpp.interior_digest);
    }

    #[test]
    fn rich_lowered_java_bundle_prepares_populated_typed_and_common_families() {
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"digest-7"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &rich_java_resolution_facts_for_test(),
        );
        let ResolutionInteriorPreparation::Prepared(bundle) =
            super::super::resolution_prepare::prepare_resolution_bundle_with_unit_keys(
                &lowered,
                None,
                &CancellationToken::default(),
            )
        else {
            panic!("uncancelled rich Java preparation must finish")
        };
        assert_eq!(bundle.semantic_language(), Language::Java);
        for family in [
            "expected_semantic_site_count",
            "expected_member_scope_property_count",
            "expected_member_owner_property_count",
        ] {
            let index = RESOLUTION_MANIFEST_COUNT_COLUMNS
                .iter()
                .position(|column| *column == family)
                .expect("manifest family");
            assert!(bundle.family_counts()[index] > 0, "{family}");
        }
    }

    #[test]
    fn progress_handler_is_cleared_on_success_error_and_panic() {
        fn assert_connection_usable(conn: &Connection) {
            let total = conn
                .query_row(
                    "WITH RECURSIVE numbers(value) AS (
                       VALUES(0) UNION ALL SELECT value + 1 FROM numbers WHERE value < 2000
                     ) SELECT SUM(value) FROM numbers",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("connection remains usable");
            assert_eq!(total, 2_001_000);
        }

        let mut conn = Connection::open_in_memory().expect("progress test connection");
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        with_resolution_progress_handler(&mut conn, &cancelled, |_| Ok(()))
            .expect("success clears progress handler");
        assert_connection_usable(&conn);

        assert!(
            with_resolution_progress_handler(&mut conn, &cancelled, |_| {
                Err::<(), _>(StoreError::new("expected"))
            })
            .is_err()
        );
        assert_connection_usable(&conn);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<()> = with_resolution_progress_handler(&mut conn, &cancelled, |_| {
                panic!("expected panic")
            });
        }));
        assert!(panic.is_err());
        assert_connection_usable(&conn);

        with_resolution_read_progress_handler(&conn, &cancelled, |_| Ok(()))
            .expect("read success clears progress handler");
        assert_connection_usable(&conn);
        assert!(
            with_resolution_read_progress_handler(&conn, &cancelled, |_| {
                Err::<(), _>(StoreError::new("expected"))
            })
            .is_err()
        );
        assert_connection_usable(&conn);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<()> = with_resolution_read_progress_handler(&conn, &cancelled, |_| {
                panic!("expected panic")
            });
        }));
        assert!(panic.is_err());
        assert_connection_usable(&conn);
    }
}

/// The store's answers to "what is this shared name's id", across requests.
///
/// A `resolution_identities.id` is a fact of the store: the writer interns a
/// name once for the whole cache, an id is never reused and a name is never
/// collected on the hot path (Decision Log, 2026-09-17), so an entry here can
/// never go stale and nothing invalidates it. Only interned ids are held; a
/// per-request id is one request's own and never leaves
/// [`SharedNameTable`].
///
/// It is a bounded moka cache with an entry cap, which is the shape the
/// heap-residency rule allows: it does not grow with the workspace. Stage 1a
/// measured about 95 prepared seeks per definition request on tract, one per
/// distinct name that request mints from a spelling; the names repeat across
/// requests, so the seek belongs to the store and not to the request.
#[derive(Clone, Debug)]
pub(crate) struct SharedNameCache {
    entries: Cache<[u8; 32], SharedNameId>,
    /// What this cache has allocated, as the heap pin's own counter sees it.
    ///
    /// The reverse-request heap pin measures a request's growth with an
    /// allocator counter and subtracts the byte-capped caches, because a cache
    /// with an explicit cap is the one structure allowed to hold an entry per
    /// file. This is that subtraction for this cache, measured rather than
    /// estimated: moka's per-entry cost is its own and an entry's 36 bytes of
    /// payload do not predict it.
    #[cfg(test)]
    allocated: Arc<std::sync::atomic::AtomicI64>,
}

impl SharedNameCache {
    /// How many names the cache holds.
    ///
    /// Tract's whole `resolution_identities` table is 22,350 rows, so this cap
    /// holds every name of a workspace of that size and still bounds a larger
    /// one; an entry is a 32-byte digest and a `u32`.
    const ENTRIES: u64 = 65_536;

    pub(crate) fn new() -> Self {
        Self {
            entries: Cache::builder().max_capacity(Self::ENTRIES).build(),
            #[cfg(test)]
            allocated: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    /// What this cache has allocated on this thread since it was built.
    #[cfg(test)]
    pub(crate) fn allocated_bytes(&self) -> i64 {
        self.allocated.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Run one cache operation, charging what it allocates to this cache.
    fn charged<T>(&self, operation: impl FnOnce(&Cache<[u8; 32], SharedNameId>) -> T) -> T {
        #[cfg(not(test))]
        {
            operation(&self.entries)
        }
        #[cfg(test)]
        {
            let before = super::resolution_operation::heap_pin_bytes();
            let result = operation(&self.entries);
            self.allocated.fetch_add(
                super::resolution_operation::heap_pin_bytes() - before,
                std::sync::atomic::Ordering::Relaxed,
            );
            result
        }
    }
}

impl Default for SharedNameCache {
    fn default() -> Self {
        Self::new()
    }
}

/// One request's answers to "what is this shared name's id".
///
/// A shared name (a lookup recipe, an intrinsic type) belongs to no file, so
/// the language-neutral lowering cannot mint its identity: it asks the store,
/// which interned the name once for the whole cache. The answers are memoized
/// here because one request lowers many blobs and the names repeat across all
/// of them, and a prepared seek is about 5 us against a hash probe's tens of
/// nanoseconds (lane LD).
///
/// It lives on the per-request `ReadySelectedResolution` and is dropped with
/// the request. It is bounded by the distinct names one request meets, not by
/// the workspace: a point request meets the names of its own closure. A
/// whole-workspace request meets more, which is the same shape the macro-walk
/// memo beside it has and the same reason it is allowed.
///
/// Behind it sits the store's own [`SharedNameCache`], which is what keeps a
/// name the previous request already looked up from costing a second seek.
/// The two are not one table: the per-request half also holds the ids this
/// request minted for names the store has not interned, and those must not
/// outlive it.
#[derive(Debug)]
pub(crate) struct SharedNameTable {
    ids: RefCell<HashMap<[u8; 32], SharedNameId>>,
    /// Only names first encountered before their committed publication differ.
    aliases: RefCell<SharedNameAliases>,
    /// How many names this request has met that the store has not interned.
    minted: std::cell::Cell<u32>,
    /// The store's cross-request answers for names it has interned.
    cache: SharedNameCache,
}

#[derive(Debug, Default)]
struct SharedNameAliases {
    from_persisted: HashMap<SharedNameId, SharedNameId>,
    to_persisted: HashMap<SharedNameId, SharedNameId>,
}

impl SharedNameTable {
    pub(crate) fn new(cache: SharedNameCache) -> Self {
        Self {
            ids: RefCell::default(),
            aliases: RefCell::default(),
            minted: std::cell::Cell::new(0),
            cache,
        }
    }

    /// An interner that answers from this store and this request's table.
    pub(crate) fn interner<'a>(&'a self, connection: &'a Connection) -> StoreSharedNames<'a> {
        StoreSharedNames {
            table: self,
            connection,
        }
    }

    /// Admit one blob's complete committed shared-name membership.
    ///
    /// Preserve IDs already used by this request and retain only differing
    /// aliases. Unencountered members remain in SQLite; the next `intern`
    /// resolves them there. Receipt-local maps die with this call, and aliases
    /// die with the existing request table, across any intervening crate stages.
    ///
    /// The publisher guarantees immutable digest/ID correspondence for unused
    /// names across receipts. Here we validate this receipt and all retained
    /// request/alias correspondences without retaining another catalog. Neither
    /// admission nor conversion issues SQL or caches request IDs in the store.
    /// Cancellation before installation leaves both alias directions unchanged.
    // B2 projection will call admission before exposing stored rows. Remove
    // this allowance when that separately owned integration lands.
    #[allow(dead_code)]
    pub(crate) fn admit_persisted_names(
        &self,
        membership: &[([u8; 32], SharedNameId)],
        cancellation: &CancellationToken,
    ) -> bool {
        let ids = self.ids.borrow();
        let mut aliases = self.aliases.borrow_mut();
        let mut by_digest = HashMap::default();
        let mut by_stored = HashMap::default();
        let mut differing = Vec::new();
        for &(digest, stored) in membership {
            if cancellation.is_cancelled() {
                return false;
            }
            assert!(
                stored.is_interned(),
                "a persisted shared name must be interned"
            );
            if let Some(previous) = by_digest.insert(digest, stored) {
                assert_eq!(
                    previous, stored,
                    "conflicting receipt digest correspondence"
                );
            }
            if let Some(previous) = by_stored.insert(stored, digest) {
                assert_eq!(
                    previous, digest,
                    "conflicting receipt stored correspondence"
                );
            }
            let request = ids.get(&digest).copied();
            if let Some(&previous) = aliases.from_persisted.get(&stored) {
                assert_eq!(
                    Some(previous),
                    request,
                    "conflicting stored alias correspondence"
                );
            }
            let Some(request) = request else {
                continue;
            };
            if request.is_interned() {
                assert_eq!(
                    request, stored,
                    "conflicting interned digest correspondence"
                );
            }
            if let Some(&previous) = aliases.to_persisted.get(&request) {
                assert_eq!(previous, stored, "conflicting request alias correspondence");
            }
            if request != stored {
                differing.push((request, stored));
            }
        }
        if cancellation.is_cancelled() {
            return false;
        }
        // One exclusive borrow covers both directions. No cancellation point
        // may split this installation after the receipt has been validated.
        for (request, stored) in differing {
            aliases.from_persisted.insert(stored, request);
            aliases.to_persisted.insert(request, stored);
        }
        true
    }
}

/// The interner one request uses: `resolution_identities` first, this
/// request's own range for a name the store has not interned.
#[derive(Debug)]
pub(crate) struct StoreSharedNames<'a> {
    table: &'a SharedNameTable,
    connection: &'a Connection,
}

impl SharedNameInterner for StoreSharedNames<'_> {
    fn from_persisted(&self, stored: SharedNameId) -> SharedNameId {
        assert!(
            stored.is_interned(),
            "a persisted shared name must be interned"
        );
        self.table
            .aliases
            .borrow()
            .from_persisted
            .get(&stored)
            .copied()
            .unwrap_or(stored)
    }

    fn to_persisted(&self, request: SharedNameId) -> Option<SharedNameId> {
        if request.is_interned() {
            Some(request)
        } else {
            self.table
                .aliases
                .borrow()
                .to_persisted
                .get(&request)
                .copied()
        }
    }

    fn intern(&self, digest: [u8; 32]) -> SharedNameId {
        if let Some(&id) = self.table.ids.borrow().get(&digest) {
            return id;
        }
        if let Some(id) = self.table.cache.charged(|entries| entries.get(&digest)) {
            debug_assert!(id.is_interned(), "the store's cache holds only store facts");
            self.table.ids.borrow_mut().insert(digest, id);
            return id;
        }
        let interned = self
            .connection
            .prepare_cached("SELECT id FROM resolution_identities WHERE identity_digest = ?1")
            .and_then(|mut statement| {
                statement
                    .query_row([digest.as_slice()], |row| row.get::<_, i64>(0))
                    .optional()
            })
            .unwrap_or_else(|error| panic!("reading the shared name table: {error}"));
        let id = match interned {
            Some(id) => {
                let id = SharedNameId::interned(id);
                // An interned id is a fact of the store and is never reused,
                // so the store keeps the answer for the next request.
                self.table
                    .cache
                    .charged(|entries| entries.insert(digest, id));
                id
            }
            None => {
                let ordinal = self.table.minted.get();
                self.table.minted.set(
                    ordinal
                        .checked_add(1)
                        .expect("a request mints fewer shared names than u32 holds"),
                );
                SharedNameId::per_request(ordinal)
            }
        };
        self.table.ids.borrow_mut().insert(digest, id);
        id
    }
}
