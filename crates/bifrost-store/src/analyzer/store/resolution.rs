//! Atomic bounded persistence for immutable resolution bundles.
//!
//! A bundle is one content-owned interior: lexical paths, lookup recipes,
//! typed transfer facts, and declared root routes. Its rows use
//! descriptor-sorted storage-local keys and never contain mounted runtime
//! identities, selected package identities, workspace paths, or revision
//! context.

use std::cell::RefCell;

use std::cmp::Ordering;

use std::fmt::Display;

use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;

use std::sync::Arc;
use std::sync::Mutex;

use rusqlite::types::ToSqlOutput;
use rusqlite::types::ValueRef;

use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::ToSql;
use rusqlite::Transaction;
use rusqlite::TransactionBehavior;
use rusqlite::params;
use rusqlite::params_from_iter;

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use crate::CancellationToken;

use crate::hash::HashMap;
use crate::hash::HashSet;

use crate::analyzer::resolution::SharedNameId;
use crate::analyzer::resolution::SharedNameInterner;

use super::resolution_manifest;

use super::resolution_prepare::resolution_rows;
use super::resolution_prepare::typed_rows;

use super::AnalyzerStore;
use super::Result;
use super::StoreError;
use super::usize_to_i64;

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
    ($($(#[$meta:meta])* $variant:ident = $code:literal,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(i64)]
        #[doc(hidden)]
        pub enum TypedFactRelation {
            $($(#[$meta])* $variant = $code,)*
        }

        impl TypedFactRelation {
            /// Every relation, in discriminant order. The pins walk it, so a
            /// variant added here is measured without being listed twice.
            #[doc(hidden)]
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// How many there are, as an array length.
            pub(super) const COUNT: usize = Self::ALL.len();

            #[doc(hidden)]
            pub const fn label(self) -> &'static str {
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
    TypeArgumentApplication = 35,
    GenericTypeAliasDefinition = 36,
    DeclaredTypeArgumentOwner = 37,
    GenericFormalOwner = 38,
    GenericFormalDefaultOwner = 39,
    TypeProductionOutput = 40,
    /// Enumerates candidate blobs embedding this terminal type name. Every
    /// embedded name has a row when parsing is complete; consumers confirm
    /// ownership from the candidate blob's own rows.
    EmbeddedTypeLookup = 41,
    /// Enumerates candidate blobs declaring this interface method name. Every
    /// declared interface method name has a row when parsing is complete;
    /// consumers confirm ownership from the candidate blob's own rows.
    InterfaceMethodLookup = 42,
    /// Enumerates candidate blobs naming this supertype. Every written supertype
    /// name has a row when parsing is complete; consumers confirm ownership from
    /// the candidate blob's own rows. Implicit roots have no row.
    SupertypeNameLookup = 43,
}

impl TypedFactRelation {
    /// The integer the family stores and every statement predicates on.
    #[doc(hidden)]
    pub const fn code(self) -> i64 {
        self as i64
    }
}

// Keep the storage family, manifest count column, and count-array order in one
// declaration. Consumers use the generated names instead of positional
// constants so adding a family cannot silently shift a reader's meaning.
macro_rules! resolution_bundle_families {
    ($macro:ident) => {
        $macro! {
            root_imports => ("root_imports", "resolution_root_imports", "expected_root_import_count", "import_site, root_scope, anchor, position, kind, bound_name", 6, 1),
            root_import_segments => ("root_import_segments", "resolution_root_import_segments", "expected_root_import_segment_count", "import_site, position, segment", 3, 2),
            root_import_demands => ("root_import_demands", "resolution_root_import_demands", "expected_root_import_demand_count", "import_site, namespace, name, target_kind, target_reference, target_name", 6, 3),
            rust_reference_contexts => ("rust_reference_contexts", "resolution_rust_reference_contexts", "expected_rust_reference_context_count", "semantic_key, source_site, source_occurrence, module_context, module_declaration, cfg_condition", 6, 1),
            rust_declaration_authorities => ("rust_declaration_authorities", "resolution_rust_declaration_authorities", "expected_rust_declaration_authority_count", "semantic_key, source_site, declaration, visibility, module_context, module_declaration, cfg_condition, activation_reason", 8, 1),
            semantic_catalog => ("semantic_catalog", "resolution_semantic_catalog", "expected_semantic_catalog_count", "local_key, identity_digest, shared_identity, import_source_site, import_start_byte, import_end_byte, import_route_kind", 7, 1),
            node_catalog => ("node_catalog", "resolution_node_catalog", "expected_node_catalog_count", "local_key, identity_digest, source_scope, kind, semantic_local_key, semantic_shared_identity, target_local_key, target_boundary_key", 8, 1),
            package_references => ("package_references", "resolution_package_references", "expected_package_reference_count", "token_key, reference_key, domain_key, choice_key, source_site, root_scope_key, namespace, lookup_key", 8, 2),
            package_members => ("package_members", "resolution_package_members", "expected_package_member_count", "token_key, definition_key, domain_key, source_site, root_scope_key, namespace, lookup_key", 7, 2),
            go_package_imports => ("go_package_imports", "resolution_go_package_imports", "expected_go_package_import_count", "definition_key, source_site, file_scope_key, spelling_choice_key, start_byte, end_byte, kind", 7, 1),
            contract_references => ("contract_references", "resolution_contract_references", "expected_contract_reference_count", "definition, member_kind, position, reference_site", 4, 3),
            path_endpoint_headers => ("path_endpoint_headers", "resolution_path_endpoint_headers", "expected_path_endpoint_header_count", "direction, identity_id, symbol_fixed_count, open_tail", 4, 4),
            path_terminal_headers => ("path_terminal_headers", "resolution_path_terminal_headers", "expected_path_terminal_header_count", "direction, identity_id, symbol_fixed_count", 3, 3),
            reference_lookup_identities => ("reference_lookup_identities", "resolution_reference_lookup_identities", "expected_reference_lookup_identity_count", "semantic_key, identity_id", 2, 1),
            root_route_segments => ("root_route_segments", "resolution_root_route_segments", "expected_root_route_segment_count", "path_key, position, segment, terminal_spelling, reference_source_site, reference_start_byte, reference_end_byte", 7, 2),
            rust_reverse_gap_candidates => ("rust_reverse_gap_candidates", "resolution_rust_reverse_gap_candidates", "expected_rust_reverse_gap_candidate_count", "site, candidate_name, namespace", 3, 3),
            semantic_sites => ("semantic_sites", "resolution_semantic_sites", "expected_semantic_site_count", "source_site, namespace, semantic_role, semantic_key", 4, 1),
            additional_definition_namespaces => ("additional_definition_namespaces", "resolution_additional_definition_namespaces", "expected_additional_definition_namespace_count", "definition_semantic_key, namespace, hoisting", 3, 2),
            definition_unit_crosswalks => ("definition_unit_crosswalks", "resolution_definition_unit_crosswalks", "expected_definition_unit_crosswalk_count", "definition_semantic_key, unit_key, identity_digest", 3, 1),
            declaration_visibility_properties => ("declaration_visibility_properties", "resolution_declaration_visibility_properties", "expected_declaration_visibility_property_count", "definition_semantic_key, visibility", 2, 1),
            declaration_access_boundaries => ("declaration_access_boundaries", "resolution_declaration_access_boundaries", "expected_declaration_access_boundary_count", "definition_semantic_key, boundary_kind, package_region, template_semantic_key", 4, 1),
            member_scope_properties => ("member_scope_properties", "resolution_member_scope_properties", "expected_member_scope_property_count", "definition_semantic_key, scope_head_node_key, scope_kind", 3, 2),
            member_owner_properties => ("member_owner_properties", "resolution_member_owner_properties", "expected_member_owner_property_count", "definition_semantic_key, owner_definition_semantic_key, owner_scope_head_node_key, member_name, member_kind, member_access, qualifier_compatibility", 7, 7),
            trait_implementations => ("trait_implementations", "resolution_trait_implementations", "expected_trait_implementation_count", "relation_key, side, position, segment, terminal_spelling, impl_site, impl_start_byte, impl_end_byte", 8, 3),
            inherent_implementations => ("inherent_implementations", "resolution_inherent_implementations", "expected_inherent_implementation_count", "relation_key, position, segment, terminal_spelling, impl_site, impl_start_byte, impl_end_byte, impl_declaration_id", 8, 2),
            typed_fact_lookups => ("typed_fact_lookups", "resolution_typed_fact_lookups", "expected_typed_fact_lookup_count", "relation, identity_id", 2, 2),
            call_argument_lists => ("call_argument_lists", "resolution_call_argument_lists", "expected_call_argument_list_count", "call_site, list_ordinal", 2, 2),
            call_arguments => ("call_arguments", "resolution_call_arguments", "expected_call_argument_count", "call_site, list_ordinal, ordinal, value_semantic_key, label", 5, 3),
            named_argument_labels => ("named_argument_labels", "resolution_named_argument_labels", "expected_named_argument_label_count", "call_site, reference_site, label", 3, 2),
            callable_parameter_lists => ("callable_parameter_lists", "resolution_callable_parameter_lists", "expected_callable_parameter_list_count", "callable_site, list_ordinal, contextual", 3, 2),
            callable_parameter_semantics => ("callable_parameter_semantics", "resolution_callable_parameter_semantics", "expected_callable_parameter_semantics_count", "callable_site, parameter_site, list_ordinal, ordinal, label, has_default", 6, 3),
            extension_receivers => ("extension_receivers", "resolution_extension_receivers", "expected_extension_receiver_count", "callable_site, receiver_type_semantic_key", 2, 1),
            import_selectors => ("import_selectors", "resolution_import_selectors", "expected_import_selector_count", "site, kind, source_name, local_name", 4, 1),
            invocation_roles => ("invocation_roles", "resolution_invocation_roles", "expected_invocation_role_count", "site, role, receiver_semantic_key, result_semantic_key", 4, 1),
            jvm_aliases => ("jvm_aliases", "resolution_jvm_aliases", "expected_jvm_alias_count", "alias, declaration_site, member_name, kind, is_static, parameter_count, status", 7, 1),
            jvm_alias_owner_segments => ("jvm_alias_owner_segments", "resolution_jvm_alias_owner_segments", "expected_jvm_alias_owner_segment_count", "alias, ordinal, spelling", 3, 2),
            package_object_exports => ("package_object_exports", "resolution_package_object_exports", "expected_package_object_export_count", "package_object_site, member_site, package_scope_node_key", 3, 2),
            package_routes => ("package_routes", "resolution_package_routes", "expected_package_route_count", "package_scope_node_key, declaration_site, placement_gap_site", 3, 1),
            package_route_segments => ("package_route_segments", "resolution_package_route_segments", "expected_package_route_segment_count", "package_scope_node_key, ordinal, spelling", 3, 2),
            singleton_relations => ("singleton_relations", "resolution_singleton_relations", "expected_singleton_relation_count", "declaration_site, enclosing_type_site, kind", 3, 1),
            compilation_imports => ("compilation_imports", "resolution_compilation_imports", "expected_compilation_import_count", "import_site", 1, 1),
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
        #[doc(hidden)]
        pub const RESOLUTION_MANIFEST_COUNT_COLUMNS: &[&str] = &{
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
        #[doc(hidden)]
        pub struct ResolutionManifestCounts(
            [u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
        );

        impl ResolutionManifestCounts {
            #[doc(hidden)]
            pub const fn from_array(
                counts: [u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
            ) -> Self {
                Self(counts)
            }

            #[doc(hidden)]
            pub const fn get(&self, family_index: usize) -> u64 {
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
            $(#[doc(hidden)]
            pub const fn $field(&self) -> u64 {
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
#[doc(hidden)]
pub const PERSISTED_RESOLUTION_TABLES: &[&str] = &[
    "resolution_additional_definition_namespaces",
    // Dormant source inputs published atomically with a prepared native blob.
    "resolution_binding_directives",
    "resolution_binding_events",
    "resolution_binding_observations",
    "resolution_binding_scopes",
    "resolution_binding_slots",
    // Milestone 6 port block 4 (lane TF): the typed facts, one table per fact
    // type, written by the tier-1 writer at index time and read by the typed
    // reader. Milestone 7 moves the write to first demand and this list moves
    // with it.
    "resolution_binding_projections",
    "resolution_call_argument_lists",
    "resolution_call_arguments",
    "resolution_call_obligations",
    "resolution_callable_parameter_lists",
    "resolution_callable_parameter_owners",
    "resolution_callable_parameter_semantics",
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
    "resolution_extension_receivers",
    // Publication authority, the workspace-wide shared identity table and the
    // per-language producer epoch.
    "resolution_fragment_interiors",
    // Milestone 6, port block 3 (lane GR): one row per lowering coverage gap
    // and one per distinct reason, written at index time as the candidate gap
    // headers they replace were.
    "resolution_gap_reasons",
    "resolution_gaps",
    "resolution_generic_type_alias_parameters",
    "resolution_generic_formals",
    "resolution_generic_formal_defaults",
    "resolution_go_package_imports",
    "resolution_identities",
    "resolution_import_selectors",
    "resolution_intrinsic_seed_identities",
    "resolution_intrinsic_seeds",
    "resolution_invocation_roles",
    "resolution_jvm_aliases",
    "resolution_jvm_alias_owner_segments",
    "resolution_member_owner_properties",
    "resolution_member_scope_properties",
    "resolution_named_argument_labels",
    "resolution_node_catalog",
    "resolution_package_members",
    "resolution_package_object_exports",
    "resolution_package_references",
    "resolution_package_route_segments",
    "resolution_package_routes",
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
    "resolution_root_imports",
    "resolution_compilation_imports",
    "resolution_root_import_segments",
    "resolution_root_import_demands",
    "resolution_rust_reverse_gap_candidates",
    "resolution_rust_declaration_authorities",
    "resolution_rust_reference_contexts",
    "resolution_semantic_catalog",
    "resolution_semantic_sites",
    // Port block 2 (lane CM), written beside the path rows at index time for
    // the same reason: the reader is a tier-1 reader and the benchmark's store
    // is built cold by the binary under test.
    "resolution_sites",
    "resolution_singleton_relations",
    "resolution_supertypes",
    "resolution_trait_implementations",
    "resolution_inherent_implementations",
    "resolution_type_arguments",
    "resolution_type_components",
    "resolution_type_productions",
    "resolution_type_frontiers",
    "resolution_type_transfers",
    "resolution_declared_type_arguments",
    "resolution_typed_fact_lookups",
    "resolution_underlying_types",
    // The per-unit summary (derivation contract, kind 2): written by the
    // language reconcile after the bundles, read by keyed lookups.
    "resolution_unit_summaries",
    "resolution_unit_summary_containers",
    "resolution_unit_summary_dependencies",
    "resolution_unit_summary_dependency_names",
    "resolution_unit_summary_exports",
    "resolution_unit_summary_gaps",
    "resolution_unit_summary_imports",
    "resolution_unit_summary_members",
    "resolution_unit_summary_placements",
    "resolution_unit_summary_reads",
    "resolution_unit_summary_versions",
];

/// One sole producer-identity bump point for the complete persisted bundle.
/// Changes to shared lowering invalidate every language, including producers
/// whose source facts are unchanged.
#[doc(hidden)]
pub const fn resolution_bundle_epoch(language: Language) -> &'static str {
    match language {
        // Reconciled above both parents: shared observed-value properties and
        // local write joins compose with the current producer and gap facts.
        // Super receivers and anonymous construction add Java producer facts
        // on top of the non-invoking member-reference and positioned
        // expression-gap bundle. A suppressed enclosing expression still
        // publishes each anonymous allocation's synthetic body identity, so
        // warm bundles from v46 lack those facts for casts and qualified
        // assignments.
        // v55 reverts #8261's v54 record and annotation parents (#8361); the
        // epoch moves forward so no v54 bundle replays without those rows.
        Language::Java => {
            "resolution-bundle-java-v55-revert-8261-producer-rules-port-6291-2026-10-23-ranked-import-destination-gaps-5969-complete-provider-inventory-absence-above-v49-classified-route-gaps-5658-root-import-publication-suppressed-anonymous-allocation-identity-5701-2026-10"
        }
        // v71: v70 (#7509) and v70 (#7391) landed together.
        // v70 (#7509): persist SpreadArgument type frontiers (role ordinal 8).
        // v70 (#7391): publish type assertion results.
        // v69 (#7509): publish embedding and interface method candidate names.
        // v68 (#7509): an initialized type-switch clause binder no longer
        // carries an InferredType gap row.
        Language::Go => {
            "resolution-bundle-go-v71-type-assertion-results-7391-classified-route-gaps-5658-root-import-publication-receiver-applicability-binding-result-separation-index-slice-component-projections-stable-transfer-codes-qualified-call-conversions-2026-10-7509-clause-guard-initializer-gap"
        }
        Language::Cpp => "resolution-bundle-cpp-v26-opaque-guard-implication-6902-2026-10",
        Language::JavaScript => {
            "resolution-bundle-javascript-v24-positioned-expression-gaps-5375-local-write-joins-5015-2026-10"
        }
        Language::TypeScript => {
            "resolution-bundle-typescript-v24-positioned-expression-gaps-5375-local-write-joins-5015-2026-10"
        }
        Language::Python => {
            "resolution-bundle-python-v24-positioned-expression-gaps-5375-local-write-joins-5015-2026-10"
        }
        // Definitionless item macros preserve existing bindings and keep
        // argument uncertainty on guessed reference sites. Only unenumerable input
        // groups open reverse inventory (#5517).
        // v122: a reference-typed generic default lowers as a TypeAlias transfer
        // (#6950), and replayed trait methods take their trait's Self frontier
        // (#6949).
        // v123: attributed items bind item fragments in macro replay, and derive
        // paths publish Macro-namespace reference sites (#6912).
        // v124: wrapper projection is a selected ConditionalPayload transfer
        // decided by resolved identity, not producer spelling (#6844).
        Language::Rust => {
            "resolution-bundle-rust-v124-duplicate-export-uncertainty-replay-call-roles-6861-inherent-impl-subjects-6394-cfg-import-precedence-6242-classified-route-gaps-5658-root-import-publication-cfg-if-conditional-macro-frontiers-5172-unique-macro-reference-gaps-5133-local-write-joins-5015-2026-10-generic-default-reference-6950-cfg-if-self-frontier-6949-macro-item-attributes-derive-sites-6912-wrapper-identity-conditional-payload-6844"
        }
        Language::Php => {
            "resolution-bundle-php-v24-positioned-expression-gaps-5375-local-write-joins-5015-2026-10"
        }
        // Self-type edges and aliases extend Scala's explicit-instantiation
        // bundle; case-class and enum companions publish binders and singleton
        // relations, and enum cases are companion members. Constructors use
        // the shared construction sites and Scala 3 extensions are scoped.
        // Projected owner paths and anonymous template owners resolve.
        // Imports select inherited members and import heads bind lexically.
        // Companion module ownership and projected apply/unapply members join
        // the inherited-member bundle.
        // An up-call's `super` receiver is the enclosing template's parent
        // identity, and an abstract or opaque type alias projects itself
        // instead of publishing an unproduced identity slot (#5685).
        // A qualified parent's type-constructor path is looked up in the scope enclosing
        // its template, not the template's own member scope (#5104).
        // v84 publishes asInstanceOf target types into expression values (#7577).
        // v85: the v84 asInstanceOf bump (#7577) and the v84 incomplete
        // function-type bump (#8200) landed together.
        // v87 reverts #8261's v86 implicit AnyRef parents (#8361); the epoch
        // moves forward so no v86 bundle replays the unbound AnyRef slots.
        Language::Scala => {
            "resolution-bundle-scala-v87-revert-8261-incomplete-function-type-8200-parent-paths-enclosing-scope-5104-producer-rules-port-6291-2026-10-23-complete-provider-inventory-and-lexical-companion-jvm-aliases-5177-classified-route-gaps-5658-scala-as-instance-of-types-7577-2026-10"
        }
        Language::CSharp => {
            "resolution-bundle-csharp-v30-preprocessor-decisions-8147-m4a-bare-lexical-roots-7314-c1-4b2p-2026-10"
        }
        Language::Ruby => {
            "resolution-bundle-ruby-v24-positioned-expression-gaps-5375-local-write-joins-5015-2026-10"
        }
        Language::Kotlin => {
            "resolution-bundle-kotlin-v63-incomplete-function-type-8200-producer-rules-port-6291-2026-10-23-narrow-nullable-function-invoke-property-shadowing-above-v59-local-constructor-initialization-above-v58-absolute-class-literal-reflection-above-v57-anonymous-dispatch-this-above-v56-dispatch-this-argument-value-above-v55-intrinsic-root-hierarchy-above-v54-above-v53-native-point-default-implicit-receiver-frames-complete-provider-inventory-absence-above-v52-class-literal-smart-cast-conversion-union-initialization-scope-header-aliases-above-v50-classified-route-gaps-2026-10"
        }
        Language::None => panic!("a resolution bundle needs an analyzable language"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PreparedResolutionBundle {
    semantic_language: Language,
    producer_epoch: &'static str,
    #[doc(hidden)]
    pub interior_digest: [u8; 32],
    #[doc(hidden)]
    pub family_counts: [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
    #[doc(hidden)]
    pub logical_rows: usize,
    #[doc(hidden)]
    pub payload_bytes: usize,
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
        {
            let _canonicalize_timing = crate::profiling::scope_with(|| {
                format!("store.resolution_bundle.canonicalize[{semantic_language:?}]")
            });
            if !rows.canonicalize(cancellation) {
                return None;
            }
        }
        let producer_epoch = resolution_bundle_epoch(semantic_language);
        let mut family_counts = rows.counts();
        let headers_digest = {
            let _headers_timing = crate::profiling::scope_with(|| {
                format!("store.resolution_bundle.headers_digest[{semantic_language:?}]")
            });
            rows.canonical_digest(
                semantic_language,
                producer_epoch,
                &family_counts,
                cancellation,
            )?
        };
        let _body_timing = crate::profiling::scope_with(|| {
            format!("store.resolution_bundle.body_digest[{semantic_language:?}]")
        });
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
        drop(_body_timing);
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

    #[doc(hidden)]
    pub const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    #[doc(hidden)]
    pub const fn producer_epoch(&self) -> &'static str {
        self.producer_epoch
    }

    #[doc(hidden)]
    pub const fn interior_digest(&self) -> [u8; 32] {
        self.interior_digest
    }

    #[doc(hidden)]
    pub const fn logical_rows(&self) -> usize {
        self.logical_rows
    }

    /// Pre-write batching estimate; committed witnesses carry measured SQLite
    /// payload bytes after interning and JSONB encoding.
    #[doc(hidden)]
    pub const fn payload_bytes(&self) -> usize {
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

    #[doc(hidden)]
    pub fn declaration_visibility_storage_cost(
        &self,
        cancellation: &CancellationToken,
    ) -> Option<(usize, usize)> {
        let rows = &self.rows.declaration_visibility_properties;
        let bytes = rows.iter().try_fold(0usize, |total, row| {
            Some(total.saturating_add(row.payload_bytes(cancellation)?))
        })?;
        Some((rows.len(), bytes))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn family_counts(&self) -> [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()] {
        self.family_counts
    }
}

impl AnalyzerStore {
    /// Install the code-owned complete-bundle epoch for one storage language.
    /// Dialect storage keys (for example `typescript:tsx` and `cpp:c`) retain
    /// their own active row while sharing the semantic producer implementation.
    #[doc(hidden)]
    pub fn ensure_resolution_producer_epoch(
        &self,
        storage_language: &str,
        semantic_language: Language,
    ) -> Result<bool> {
        assert!(!storage_language.is_empty());
        let storage_language = storage_language.to_owned();
        let producer_epoch = resolution_bundle_epoch(semantic_language);
        self.execute_selection_publication(move |conn| {
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
            // Every summary of this language was derived from bundles of the old
            // epoch; withdraw them so no reader finds one before the next
            // reconcile derives the units again.
            if tx.execute(
                super::unit_summaries::DELETE_LANGUAGE_VERSIONS_SQL,
                [&storage_language],
            )? > 0
            {
                tx.execute(super::unit_summaries::DELETE_UNBOUND_SUMMARIES_SQL, [])?;
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
#[doc(hidden)]
pub fn with_resolution_read_progress_handler<T>(
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

pub(super) fn read_resolution_statement<T>(
    conn: &Connection,
    cancellation: &CancellationToken,
    job: impl FnOnce(&Connection) -> Result<Option<T>>,
) -> Result<Option<T>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    match with_resolution_read_progress_handler(conn, cancellation, job) {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
        Err(error) => Err(error),
        Ok(_) if cancellation.is_cancelled() => Ok(None),
        Ok(result) => Ok(result),
    }
}

pub(super) fn json_array<T: Display>(values: impl IntoIterator<Item = T>) -> String {
    let mut out = String::from("[");
    for (position, value) in values.into_iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
    out
}

/// One batch of integer pairs as a JSON array of two-element arrays.
/// The caller owns the keys and drops this buffer after its queries finish.
pub(super) fn json_pair_array(pairs: impl Iterator<Item = (i64, i64)>) -> String {
    let mut out = String::from("[");
    for (position, (first, second)) in pairs.enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push('[');
        out.push_str(&first.to_string());
        out.push(',');
        out.push_str(&second.to_string());
        out.push(']');
    }
    out.push(']');
    out
}

pub(super) fn nonnegative_i64(row: &Row<'_>, column: usize, label: &str) -> Result<i64> {
    let value = row.get::<_, i64>(column)?;
    nonnegative_i64_value(value, label)
}

pub(super) fn nonnegative_i64_value(value: i64, label: &str) -> Result<i64> {
    if value < 0 {
        return Err(StoreError::new(format!(
            "{label} cannot be negative: {value}"
        )));
    }
    Ok(value)
}

pub(super) fn mount_ordinal(
    row: &Row<'_>,
    column: usize,
    label: &str,
) -> Result<crate::analyzer::resolution::SelectedResolutionMountOrdinal> {
    let value = nonnegative_i64(row, column, label)?;
    let value = u32::try_from(value)
        .map_err(|_| StoreError::new(format!("{label} does not fit u32: {value}")))?;
    Ok(crate::analyzer::resolution::SelectedResolutionMountOrdinal::new(value))
}

pub(super) fn require_selected_mount_record(
    record: Option<Arc<super::resolution_selection::SelectedResolutionMountRecord>>,
    ordinal: crate::analyzer::resolution::SelectedResolutionMountOrdinal,
    reader: &str,
) -> Result<Arc<super::resolution_selection::SelectedResolutionMountRecord>> {
    record.ok_or_else(|| {
        StoreError::new(format!(
            "selected {reader} row names unknown mount ordinal {}",
            ordinal.get()
        ))
    })
}

pub(super) enum EndpointLookupShape<'a, T> {
    Every,
    Unkeyed,
    Fixed(&'a T),
}

pub(super) fn endpoint_lookup_shape<T>(
    first_fixed: Option<&T>,
    has_open_tail: bool,
) -> EndpointLookupShape<'_, T> {
    match first_fixed {
        Some(symbol) => EndpointLookupShape::Fixed(symbol),
        None if has_open_tail => EndpointLookupShape::Every,
        None => EndpointLookupShape::Unkeyed,
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

    let mut interner = IdentityInterner::default();
    for (spec, rows) in PreparedResolutionBundleRows::family_specs()
        .into_iter()
        .zip(bundle.rows.families())
    {
        // Boundary validation needs the canonical template's type-body row,
        // which is published with the typed families below (including locals
        // that have no definition/unit crosswalk).
        if spec.name == "declaration_access_boundaries" {
            continue;
        }
        if let Some(digest_column) = interned_identity_column(spec.name) {
            if !insert_interned_header_family(
                tx,
                blob_id,
                spec,
                digest_column,
                rows,
                &mut interner,
                cancellation,
            )? {
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
    if !insert_row_families(tx, blob_id, bundle, &mut interner, cancellation)? {
        return Ok(false);
    }
    if !insert_gap_rows(tx, blob_id, bundle, &mut interner, cancellation)? {
        return Ok(false);
    }
    if !insert_typed_fact_rows(tx, blob_id, bundle, &mut interner, cancellation)? {
        return Ok(false);
    }
    let boundary_spec = PreparedResolutionBundleRows::family_specs()
        [ResolutionManifestFamilyIndex::declaration_access_boundaries as usize];
    if !insert_resolution_family(
        tx,
        blob_id,
        boundary_spec,
        &bundle.rows.declaration_access_boundaries,
        cancellation,
    )? {
        return Ok(false);
    }
    if crate::cache_db::seal_validates(blob_id) {
        tx.prepare_cached(resolution_manifest::COMPLETE_PUBLICATION_COUNTS_SQL)?
            .query_row([blob_id], |row| {
                for (index, expected) in bundle.family_counts.iter().enumerate() {
                    let actual: usize = row.get(index)?;
                    assert_eq!(
                        actual, *expected,
                        "complete resolution family {}",
                        RESOLUTION_MANIFEST_COUNT_COLUMNS[index]
                    );
                }
                Ok(())
            })?;
    }
    let payload_bytes: i64 = tx
        .prepare_cached(resolution_manifest::COMPLETE_PUBLICATION_PAYLOAD_BYTES_SQL)?
        .query_row([blob_id], |row| row.get(0))?;
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
    interner: &mut IdentityInterner,
    cancellation: &CancellationToken,
) -> Result<bool> {
    // Every shared name of the blob's catalog, not only the ones a header
    // family or a path body names. An interior produced for this blob later
    // asserts that each of its shared ids is one of these rows.
    for digest in &bundle.shared_name_digests {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        interner.intern(tx, digest)?;
    }
    {
        // One statement, no read: a name's recipe is the same wherever it is
        // seen, so the first blob that interns it fills the columns and every
        // later blob's write is a no-op the `WHERE` clause drops. Tract has
        // 484,527 recipe entries over 183 interiors and 22,206 distinct shared
        // names, so an unconditional UPDATE would be twenty-two writes per
        // name that change nothing. A name the interner has already seen
        // filled, in the store or by an earlier recipe row of this blob, is
        // one of those no-ops and is not even sent.
        let mut recipes = tx.prepare_cached(
            "INSERT INTO resolution_identities(
               identity_digest, semantic_language, namespace, spelling
             ) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(identity_digest) DO UPDATE
               SET semantic_language = excluded.semantic_language,
                   namespace = excluded.namespace,
                   spelling = excluded.spelling
               WHERE resolution_identities.semantic_language IS NULL",
        )?;
        for recipe in &bundle.recipe_rows {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if !interner.recipes_filled.insert(recipe.identity_digest) {
                continue;
            }
            recipes.execute(rusqlite::params![
                recipe.identity_digest.as_slice(),
                recipe.semantic_language,
                recipe.namespace,
                recipe.spelling,
            ])?;
        }
    }
    let mut shared_ids = Vec::with_capacity(bundle.path_rows.shared.len());
    for digest in &bundle.path_rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        shared_ids.push(interner.intern(tx, digest)?);
    }
    if !insert_json_rows(
        tx,
        "INSERT INTO resolution_sites(
           blob_id, site, role, namespace, site_kind, start_byte, end_byte,
           unqualified, owner, receiver_origin, go_spelling_namespace, go_definition_namespaces, go_package_qualifier
         ) SELECT json_extract(value, '$[0]'),
                json_extract(value, '$[1]'),
                json_extract(value, '$[2]'),
                json_extract(value, '$[3]'),
                json_extract(value, '$[4]'),
                json_extract(value, '$[5]'),
                json_extract(value, '$[6]'),
                json_extract(value, '$[7]'),
                json_extract(value, '$[8]'),
                json_extract(value, '$[9]'),
                json_extract(value, '$[10]'),
                json_extract(value, '$[11]'),
                json_extract(value, '$[12]')
         FROM json_each(?1)",
        bundle.site_rows.iter().map(|row| (
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
        )),
        cancellation,
    )? {
        return Ok(false);
    }
    let shared_id = |slot: Option<u32>| {
        slot.map(|slot| shared_ids[usize::try_from(slot).expect("a slot fits usize")])
    };
    if !insert_json_rows(
        tx,
        "INSERT INTO resolution_paths(
           blob_id, path, start_node, start_lead_local, start_lead_identity,
           start_lead_scoped, end_node, end_lead_local, end_lead_identity,
           end_lead_scoped, root_terminal, body, end_fixed_key, end_open_tail,
           activation_ordinal
         ) SELECT json_extract(value, '$[0]'),
                json_extract(value, '$[1]'),
                json_extract(value, '$[2]'),
                json_extract(value, '$[3]'),
                json_extract(value, '$[4]'),
                json_extract(value, '$[5]'),
                json_extract(value, '$[6]'),
                json_extract(value, '$[7]'),
                json_extract(value, '$[8]'),
                json_extract(value, '$[9]'),
                json_extract(value, '$[10]'),
                jsonb(json_extract(value, '$[11]')),
                json_extract(value, '$[12]'),
                json_extract(value, '$[13]'),
                json_extract(value, '$[14]')
         FROM json_each(?1)",
        bundle.path_rows.rows.iter().map(|row| {
            let root = row.root_endpoint.as_ref().map(|endpoint| {
                let mut key = resolution_rows::RootKeyBuilder::default();
                for (symbol, scoped) in &endpoint.symbols {
                    match symbol {
                        resolution_rows::PathBodyToken::Int(local) => {
                            key.push(Some(*local), None, *scoped)
                        }
                        resolution_rows::PathBodyToken::Shared(slot) => {
                            key.push(None, shared_id(Some(*slot)), *scoped)
                        }
                        other => unreachable!("a root symbol is an identity, not {other:?}"),
                    }
                }
                (key.finish().0, i64::from(endpoint.open_tail))
            });
            debug_assert_eq!(root.is_some(), row.end_node == -1);
            let (root_key, root_tail) = root.unzip();
            (
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
                root_key,
                root_tail,
                row.root_import_activation.map(i64::from),
            )
        }),
        cancellation,
    )? {
        return Ok(false);
    }
    Ok(true)
}

/// Transport one table's rows in insertion order, bounded by SQLite's actual
/// connection length limit. Measure encoded bytes, rather than guessing a row
/// count: path bodies and spellings have variable lengths. The one parameter
/// does not grow the bound-variable count. Nothing survives this publication.
fn insert_json_rows<R: serde::Serialize>(
    tx: &Transaction<'_>,
    sql: &str,
    rows: impl Iterator<Item = R>,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let limit = usize::try_from(tx.limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)?)
        .expect("SQLite's length limit is nonnegative");
    let mut statement = tx.prepare_cached(sql)?;
    let mut batch = String::from("[");
    for row in rows {
        let row = serde_json::to_string(&row).expect("publication values serialize as JSON");
        // Include the separating comma and closing bracket in the measurement.
        if batch.len() > 1 && batch.len() + row.len() + 2 > limit {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            batch.push(']');
            statement.execute([&batch])?;
            batch.clear();
            batch.push('[');
        }
        if batch.len() > 1 {
            batch.push(',');
        }
        batch.push_str(&row);
    }
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    if batch.len() > 1 {
        batch.push(']');
        statement.execute([&batch])?;
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
    interner: &mut IdentityInterner,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let mut lookup_ids = Vec::with_capacity(bundle.gap_rows.shared.len());
    for digest in &bundle.gap_rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        lookup_ids.push(interner.intern(tx, digest)?);
    }
    if !insert_json_rows(
        tx,
        "INSERT INTO resolution_gap_reasons(blob_id, reason, site, origin) SELECT json_extract(value, '$[0]'),
                json_extract(value, '$[1]'),
                json_extract(value, '$[2]'),
                json_extract(value, '$[3]')
         FROM json_each(?1)",
        bundle
            .gap_rows
            .reasons
            .iter()
            .map(|row| (blob_id, row.reason, row.site, row.origin)),
        cancellation,
    )? {
        return Ok(false);
    }
    if !insert_json_rows(
        tx,
        "INSERT INTO resolution_gaps(blob_id, covers, subject, lookup, gap, reason) SELECT json_extract(value, '$[0]'),
                json_extract(value, '$[1]'),
                json_extract(value, '$[2]'),
                json_extract(value, '$[3]'),
                json_extract(value, '$[4]'),
                json_extract(value, '$[5]')
         FROM json_each(?1)",
        bundle.gap_rows.rows.iter().map(|row| {
            (
                blob_id,
                row.covers,
                row.subject,
                row.lookup.map_or(0, |slot| lookup_ids
                    [usize::try_from(slot).expect("a slot fits usize")]),
                row.gap,
                row.reason
            )
        }),
        cancellation,
    )? {
        return Ok(false);
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
    interner: &mut IdentityInterner,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let rows = &bundle.typed_fact_rows;
    let mut shared_ids = Vec::with_capacity(rows.shared.len());
    for digest in &rows.shared {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        shared_ids.push(interner.intern(tx, digest)?);
    }
    let shared_id = |slot: u32| shared_ids[usize::try_from(slot).expect("a slot fits usize")];
    let body = |tokens: &[resolution_rows::PathBodyToken]| {
        resolution_rows::render_path_body(tokens, &shared_ids)
    };
    let optional_body = |tokens: &Option<Vec<resolution_rows::PathBodyToken>>| {
        tokens.as_ref().map(|tokens| body(tokens))
    };

    if !insert_json_rows(
        tx,
        "INSERT INTO resolution_type_frontiers(blob_id, slot, role, identity_reference) SELECT json_extract(value, '$[0]'),
                json_extract(value, '$[1]'),
                json_extract(value, '$[2]'),
                json_extract(value, '$[3]')
         FROM json_each(?1)",
        rows.type_frontiers
            .iter()
            .map(|row| (blob_id, row.slot, row.role, row.identity_reference)),
        cancellation,
    )? {
        return Ok(false);
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_type_transfers(
           blob_id, source_slot, rule, target_slot, kind, indirection_delta,
           reference_indirection_delta, value_transform, completion
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, jsonb(?9))",
        )?;
        for row in &rows.type_transfers {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
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
    }
    {
        let mut statement = tx.prepare_cached("INSERT INTO resolution_type_productions(blob_id, output_slot, constructor, length_token, element_slot) VALUES(?1, ?2, ?3, ?4, ?5)")?;
        for row in &rows.type_productions {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.output_slot,
                row.constructor,
                row.length_token,
                row.element_slot
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_type_components(
           blob_id, container_slot, constructor, kind, component_slot
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
        )?;
        for row in &rows.type_components {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.container_slot,
                row.constructor,
                row.kind,
                row.component_slot,
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_type_arguments(
           blob_id, application_slot, ordinal, argument_slot, indirection_delta,
           reference_indirection_delta
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in &rows.type_arguments {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.application_slot,
                row.ordinal,
                row.argument_slot,
                row.indirection_delta,
                row.reference_indirection_delta,
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_declared_type_arguments(
           blob_id, owner_slot, ordinal, argument_slot
         ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.declared_type_arguments {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.owner_slot,
                row.ordinal,
                row.argument_slot,
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_underlying_types(blob_id, definition, slot)
         VALUES(?1, ?2, ?3)",
        )?;
        for row in &rows.underlying_types {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![blob_id, row.definition, row.slot])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_generic_type_alias_parameters(
           blob_id, alias_definition, ordinal, parameter_definition, target_slot,
           indirection_delta, reference_indirection_delta
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &rows.generic_type_alias_parameters {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.alias_definition,
                row.ordinal,
                row.parameter_definition,
                row.target_slot,
                row.indirection_delta,
                row.reference_indirection_delta,
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_generic_formal_defaults(
           blob_id, owner_definition, ordinal, default_slot
         ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.generic_formal_defaults {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.owner_definition,
                row.ordinal,
                row.default_slot,
            ])?;
        }
    }

    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_generic_formals(
           blob_id, owner_definition, ordinal, parameter_definition
         ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.generic_formals {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.owner_definition,
                row.ordinal,
                row.parameter_definition,
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_intrinsic_seeds(
           blob_id, slot, kind, spelling, possible_values, completion
         ) VALUES(?1, ?2, ?3, ?4, jsonb(?5), jsonb(?6))",
        )?;
        for row in &rows.intrinsic_seeds {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.slot,
                row.kind,
                row.spelling,
                body(&row.possible_values),
                optional_body(&row.completion),
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_intrinsic_seed_identities(blob_id, identity_id, slot)
         VALUES(?1, ?2, ?3)",
        )?;
        for row in &rows.intrinsic_seed_identities {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                shared_id(row.identity),
                row.slot
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_binding_projections(blob_id, reference, output_slot, kind)
         VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.binding_projections {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.reference,
                row.output_slot,
                row.kind
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_qualified_routes(
           blob_id, reference, precedence_ordinal, qualifier_slot, lookup,
           source_lookup, namespace, projection_output_slot, projection_kind,
           coarse_gap_reason, open_member_surface
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for row in &rows.qualified_routes {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
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
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_declaration_types(blob_id, definition, role, slot)
         VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.declaration_types {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.definition,
                row.role,
                row.slot
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_deferred_member_owners(blob_id, definition, seq, lookup, body)
         VALUES(?1, ?2, ?3, ?4, jsonb(?5))",
        )?;
        for row in &rows.deferred_member_owners {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.definition,
                row.seq,
                shared_id(row.lookup),
                body(&row.body),
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_construction_requirements(
           blob_id, definition, required_owner_definition, kind
         ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &rows.construction_requirements {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.definition,
                row.required_owner_definition,
                row.kind
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached("INSERT INTO resolution_supertypes(blob_id, definition, reference, frontier, kind, parent_ordinal)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)")?;
        for row in &rows.supertypes {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.definition,
                row.reference,
                row.frontier,
                row.kind,
                row.parent_ordinal
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_definition_property_gaps(
           blob_id, definition, seq, kind, frontier, reason, site
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &rows.definition_property_gaps {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.definition,
                row.seq,
                row.kind,
                row.frontier,
                row.reason,
                row.site
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_call_obligations(
           blob_id, callee_reference, call, receiver_slot, result_slot,
           explicit_type_argument_count, applicability_reason, argument_slots,
           type_argument_slots, eligible_rules, completion
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, jsonb(?8), jsonb(?9), jsonb(?10), jsonb(?11))",
        )?;
        for row in &rows.call_obligations {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
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
    }
    {
        let mut statement = tx.prepare_cached("INSERT INTO resolution_callable_parameter_owners(blob_id, parameter_definition, signature_definition)
         VALUES(?1, ?2, ?3)")?;
        for row in &rows.callable_parameter_owners {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![
                blob_id,
                row.parameter_definition,
                row.signature_definition
            ])?;
        }
    }
    {
        let mut statement = tx.prepare_cached(
            "INSERT INTO resolution_callable_signatures(blob_id, definition, body)
         VALUES(?1, ?2, jsonb(?3))",
        )?;
        for row in &rows.callable_signatures {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(rusqlite::params![blob_id, row.definition, body(&row.body)])?;
        }
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

/// The shared identities one bundle's write names, each read from the store
/// once. The identity table is workspace-wide and immutable: a digest keeps
/// its id for the life of the cache, so the first read is the authority for
/// every later cell, path body, gap or typed row of the bundle that names the
/// same digest. The map lives for one bundle's write and is dropped with it.
#[derive(Default)]
struct IdentityInterner {
    ids: HashMap<[u8; 32], i64>,
    /// Names whose lookup recipe is filled: in the store when the name was
    /// read, or by a recipe row of this bundle.
    recipes_filled: HashSet<[u8; 32]>,
}

impl IdentityInterner {
    fn intern(&mut self, tx: &Transaction<'_>, digest: &[u8; 32]) -> Result<i64> {
        if let Some(id) = self.ids.get(digest) {
            return Ok(*id);
        }
        let stored = tx
            .prepare_cached(
                "SELECT id, semantic_language IS NOT NULL
                 FROM resolution_identities WHERE identity_digest = ?1",
            )?
            .query_row([digest.as_slice()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
            })
            .optional()?;
        let id = match stored {
            Some((id, recipe_filled)) => {
                if recipe_filled {
                    self.recipes_filled.insert(*digest);
                }
                id
            }
            None => tx
                .prepare_cached(
                    "INSERT INTO resolution_identities(identity_digest) VALUES(?1) RETURNING id",
                )?
                .query_row([digest.as_slice()], |row| row.get::<_, i64>(0))?,
        };
        self.ids.insert(*digest, id);
        Ok(id)
    }
}

/// Intern one shared identity digest and return its id, for tests that
/// publish names without a bundle.
#[cfg(test)]
fn intern_resolution_identity(tx: &Transaction<'_>, digest: &[u8; 32]) -> Result<i64> {
    IdentityInterner::default().intern(tx, digest)
}

fn insert_interned_header_family(
    tx: &Transaction<'_>,
    blob_id: i64,
    spec: ResolutionFamilySpec,
    digest_column: usize,
    rows: &[PreparedResolutionRow],
    interner: &mut IdentityInterner,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if rows.is_empty() {
        return Ok(!cancellation.is_cancelled());
    }
    let mut identities = Vec::with_capacity(rows.len());
    for row in rows {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        identities.push(match &row.values[digest_column] {
            PreparedResolutionValue::Digest(digest) => Some(interner.intern(tx, digest)?),
            PreparedResolutionValue::Null => None,
            other => panic!("{} identity column holds {other:?}", spec.name),
        });
    }
    let row_sql = format!("({})", vec!["?"; spec.arity + 1].join(", "));
    let mut values = Vec::<&dyn ToSql>::with_capacity(rows.len() * (spec.arity + 1));
    for (row, identity) in rows.iter().zip(&identities) {
        values.push(&blob_id);
        for (position, value) in row.values.iter().enumerate() {
            if position == digest_column {
                values.push(identity);
            } else {
                values.push(value);
            }
        }
    }
    Ok(super::row_batch::insert_rows(
        tx,
        &format!(
            "INSERT INTO {}(blob_id, {}) VALUES",
            spec.table, spec.columns
        ),
        &row_sql,
        spec.arity + 1,
        &values,
        cancellation,
    )?)
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
    let row_sql = format!(
        "({})",
        (1..=spec.arity + 1)
            .map(|position| {
                if matches!(
                    (spec.name, position),
                    ("rust_reference_contexts", 7) | ("rust_declaration_authorities", 5 | 8)
                ) {
                    "jsonb(?)"
                } else {
                    "?"
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut values = Vec::<&dyn ToSql>::with_capacity(rows.len() * (spec.arity + 1));
    for row in rows {
        values.push(&blob_id);
        values.extend(row.values.iter().map(|value| value as &dyn ToSql));
    }
    Ok(super::row_batch::insert_rows(
        tx,
        &format!(
            "INSERT INTO {}(blob_id, {}) VALUES",
            spec.table, spec.columns
        ),
        &row_sql,
        spec.arity + 1,
        &values,
        cancellation,
    )?)
}

#[cfg(test)]
mod tests {
    use super::super::resolution_prepare::ResolutionInteriorPreparation;

    use crate::analyzer::resolution::BindingFragmentId;
    use crate::analyzer::resolution::rich_java_resolution_facts_for_test;

    use brokk_bifrost_test_macros::hardwon;

    use super::*;

    #[test]
    fn store_tests_validate_every_seal() {
        assert!(
            crate::cache_db::seal_validates(1),
            "store tests must enable brokk-bifrost-core/test-support, or production sampling skips 63 of 64 seal checks"
        );
    }

    #[test]
    fn json_publication_chunks_preserve_sqlite_values_and_rowids() {
        let mut connection = crate::cache_db::open_in_memory_store_connection().unwrap();
        connection.execute_batch("CREATE TABLE batched(id INTEGER PRIMARY KEY, ordinal INTEGER, body BLOB, optional TEXT, flag INTEGER);
                                  CREATE TABLE single(id INTEGER PRIMARY KEY, ordinal INTEGER, body BLOB, optional TEXT, flag INTEGER);").unwrap();
        let tx = connection.transaction().unwrap();
        let text =
            serde_json::to_string(&["quotes\" and slashes\\ and unicode \u{00e9}"; 8]).unwrap();
        for ordinal in 0..10 {
            tx.execute(
                "INSERT INTO single(ordinal,body,optional,flag) VALUES(?1,jsonb(?2),?3,?4)",
                params![ordinal, text, Option::<String>::None, ordinal % 2 == 0],
            )
            .unwrap();
        }
        // This is deliberately below the encoded batch size, above every
        // individual row and SQL statement. Exercise the real SQLite boundary.
        let previous = tx
            .set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024)
            .unwrap();
        assert!(insert_json_rows(&tx,
            "INSERT INTO batched(ordinal,body,optional,flag) SELECT json_extract(value,'$[0]'),jsonb(json_extract(value,'$[1]')),json_extract(value,'$[2]'),json_extract(value,'$[3]') FROM json_each(?1)",
            (0..10).map(|ordinal| (ordinal, &text, Option::<String>::None, ordinal % 2 == 0)),
            &CancellationToken::new()).unwrap());
        tx.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, previous)
            .unwrap();
        let count: i64 = tx
            .query_row("SELECT count(*) FROM batched", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 10, "the chunked writer must run");
        let different: i64 = tx
            .query_row(
                "SELECT count(*) FROM (SELECT * FROM single EXCEPT SELECT * FROM batched)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            different, 0,
            "JSONB bytes, nulls, booleans and rowids are identical"
        );
    }

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
            let cache = SharedNameCache::default();
            let table = SharedNameTable::new(cache.clone());
            let synthetic = table.interner(&connection).intern([99; 32]);
            let first = table.interner(&connection).intern([1; 32]);
            let second = table.interner(&connection).intern([2; 32]);
            assert_ne!(first, second);
            assert!(!first.is_interned());
            assert_eq!(table.interner(&connection).to_persisted(first), None);
            assert!(
                cache.shared_name([1; 32]).is_none(),
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
            assert_eq!(cache.shared_name([1; 32]), Some(stored_first));
            assert_eq!(cache.shared_name([2; 32]), Some(stored_second));
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
            let table = SharedNameTable::new(SharedNameCache::default());
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
        let table = SharedNameTable::new(SharedNameCache::default());
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(!table.admit_persisted_names(&[], &cancelled));
        assert!(table.admit_persisted_names(&[], &CancellationToken::new()));
    }

    #[test]
    fn shared_name_admission_rejects_conflicts_before_installing_aliases() {
        let mut connection = shared_name_connection();
        let table = SharedNameTable::new(SharedNameCache::default());
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
    #[hardwon(
        "3da13ca2218b: resolution publication identity omitted named header families or depended on row order"
    )]
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

    #[test]
    fn rich_lowered_java_bundle_prepares_populated_typed_and_common_families() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
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
}

/// A shared handle to the store's one weighted cache budget.
#[doc(hidden)]
pub type SharedNameCache = super::cache_budget::StoreCacheBudget;

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
#[doc(hidden)]
pub struct SharedNameTable {
    ids: RefCell<HashMap<[u8; 32], SharedNameId>>,
    digests_by_id: RefCell<HashMap<SharedNameId, [u8; 32]>>,
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
    #[doc(hidden)]
    pub fn new(cache: SharedNameCache) -> Self {
        Self {
            ids: RefCell::default(),
            digests_by_id: RefCell::default(),
            aliases: RefCell::default(),
            minted: std::cell::Cell::new(0),
            cache,
        }
    }

    /// An interner that answers from this store and this request's table.
    #[doc(hidden)]
    pub fn interner<'a>(&'a self, connection: &'a Connection) -> StoreSharedNames<'a> {
        StoreSharedNames {
            table: self,
            connection,
        }
    }

    pub(crate) fn remember_identity(&self, digest: [u8; 32], id: SharedNameId) {
        if let Some(previous) = self.ids.borrow_mut().insert(digest, id) {
            assert_eq!(previous, id, "one digest keeps one request identity");
        }
        if let Some(previous) = self.digests_by_id.borrow_mut().insert(id, digest) {
            assert_eq!(previous, digest, "one request identity keeps one digest");
        }
    }

    /// Remember an observed catalog identity without making the next request
    /// repeat its seek. Only the committed ID enters the bounded store cache;
    /// the request may already have a different, publication-local alias.
    pub(crate) fn remember_stored_identity(
        &self,
        digest: [u8; 32],
        stored: SharedNameId,
        request: SharedNameId,
    ) {
        assert!(
            stored.is_interned(),
            "the store cache holds only committed IDs"
        );
        self.remember_identity(digest, request);
        self.cache.insert_shared_name(digest, stored);
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
    #[doc(hidden)]
    pub fn admit_persisted_names(
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
#[doc(hidden)]
pub struct StoreSharedNames<'a> {
    table: &'a SharedNameTable,
    connection: &'a Connection,
}

impl SharedNameInterner for StoreSharedNames<'_> {
    fn digest_for_id(&self, id: SharedNameId) -> Option<[u8; 32]> {
        self.table.digests_by_id.borrow().get(&id).copied()
    }

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
        if let Some(id) = self.table.cache.shared_name(digest) {
            debug_assert!(id.is_interned(), "the store's cache holds only store facts");
            self.table.remember_identity(digest, id);
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
                self.table.cache.insert_shared_name(digest, id);
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
        self.table.remember_identity(digest, id);
        id
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_dump.rs"]
mod resolution_dump;
