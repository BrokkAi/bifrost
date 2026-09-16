//! Canonical storage-local rows prepared from caller-owned normalized facts.
//!
//! Preparation does not open a database, install an epoch, or publish rows.
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::{Language, canonical_hash::CanonicalHasher};
use std::cmp::Ordering;

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
    arity: usize,
    key_arity: usize,
}

// Keep the storage family, manifest count column, and count-array order in one
// declaration. Consumers use the generated names instead of positional
// constants so adding a family cannot silently shift a reader's meaning.
macro_rules! resolution_bundle_families {
    ($macro:ident) => {
        $macro! {
            semantic_terms => ("semantic_terms", "resolution_semantic_terms", "expected_semantic_term_count", "semantic_key, identity_space, identity_digest", 3, 1),
            lookup_semantic_recipes => ("lookup_semantic_recipes", "resolution_lookup_semantic_recipes", "expected_lookup_semantic_recipe_count", "semantic_key, namespace, spelling", 3, 1),
            stack_variables => ("stack_variables", "resolution_stack_variables", "expected_stack_variable_count", "variable_key, local_digest", 2, 1),
            nodes => ("nodes", "resolution_nodes", "expected_node_count", "node_key, local_digest, node_kind, semantic_key, jump_scope_node_key, jump_scope_boundary_key, completion_kind, expected_completion_reason_count", 8, 1),
            reference_sites => ("reference_sites", "resolution_reference_sites", "expected_reference_site_count", "node_key, reference_site, namespace, site_kind, start_byte, end_byte, unqualified, owner_known, owner_semantic_key, callable_receiver_origin", 10, 1),
            semantic_sites => ("semantic_sites", "resolution_semantic_sites", "expected_semantic_site_count", "source_site, namespace, semantic_role, semantic_key, node_key, definition_graph_domain", 6, 1),
            additional_definition_namespaces => ("additional_definition_namespaces", "resolution_additional_definition_namespaces", "expected_additional_definition_namespace_count", "definition_semantic_key, namespace, hoisting", 3, 2),
            definition_unit_crosswalks => ("definition_unit_crosswalks", "resolution_definition_unit_crosswalks", "expected_definition_unit_crosswalk_count", "definition_semantic_key, unit_key", 2, 1),
            gap_reason_provenance => ("gap_reason_provenance", "resolution_gap_reason_provenance", "expected_gap_reason_count", "reason_semantic_key, source_site, gap_origin", 3, 1),
            reference_completion_reasons => ("reference_completion_reasons", "resolution_reference_completion_reasons", "expected_reference_completion_reason_count", "node_key, position, reason_kind, cyclic_path_key, semantic_key, boundary_status, source_site, gap_origin", 8, 2),
            fragment_gaps => ("fragment_gaps", "resolution_fragment_gaps", "expected_fragment_gap_count", "gap_key, local_digest, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 1),
            reference_enumeration_gaps => ("reference_enumeration_gaps", "resolution_reference_enumeration_gaps", "expected_enumeration_gap_count", "gap_key, local_digest, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 1),
            reference_enumeration_impacts => ("reference_enumeration_impacts", "resolution_reference_enumeration_impacts", "expected_reference_enumeration_impact_count", "gap_key, position, occurrence_role, exact_lookup_semantic_key, domain", 5, 2),
            candidate_gaps => ("candidate_gaps", "resolution_candidate_gaps", "expected_candidate_gap_count", "direction, gap_key, local_digest, coverage_scope, endpoint_node_key, endpoint_boundary_key, lookup_semantic_key, reason_kind, cyclic_path_key, semantic_key, boundary_status", 11, 2),
            partial_paths => ("partial_paths", "resolution_partial_paths", "expected_path_count", "path_key, local_digest, start_node_key, start_boundary_key, end_node_key, end_boundary_key, start_symbol_tail_key, end_symbol_tail_key, start_symbol_fixed_count, end_symbol_fixed_count, start_first_symbol_key, end_first_symbol_key, completion_kind, body", 14, 1),
            type_frontiers => ("type_frontiers", "resolution_type_frontiers", "expected_type_frontier_count", "frontier_key, frontier_kind, slot_role, synthetic_source_site", 4, 1),
            type_transfer_rules => ("type_transfer_rules", "resolution_type_transfer_rules", "expected_type_transfer_rule_count", "rule_semantic_key, source_frontier_key, target_frontier_key, transfer_kind, indirection_delta, value_transform, runtime_addressable, completion_kind, expected_completion_reason_count", 9, 1),
            type_transfer_rule_completion_reasons => ("type_transfer_rule_completion_reasons", "resolution_type_transfer_rule_completion_reasons", "expected_type_transfer_rule_completion_reason_count", "rule_semantic_key, position, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 2),
            type_frontier_gaps => ("type_frontier_gaps", "resolution_type_frontier_gaps", "expected_type_frontier_gap_count", "frontier_key, gap_key, local_digest, reason_kind, cyclic_path_key, semantic_key, boundary_status, source_site, gap_origin", 9, 2),
            intrinsic_type_seeds => ("intrinsic_type_seeds", "resolution_intrinsic_type_seeds", "expected_intrinsic_type_seed_count", "frontier_key, intrinsic_kind, completion_kind, expected_value_count, expected_completion_reason_count", 5, 1),
            intrinsic_type_seed_values => ("intrinsic_type_seed_values", "resolution_intrinsic_type_seed_values", "expected_intrinsic_type_seed_value_count", "frontier_key, position, value_category, type_identity_semantic_key, indirection, runtime_addressable", 6, 2),
            intrinsic_type_seed_completion_reasons => ("intrinsic_type_seed_completion_reasons", "resolution_intrinsic_type_seed_completion_reasons", "expected_intrinsic_type_seed_completion_reason_count", "frontier_key, position, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 2),
            binding_projections => ("binding_projections", "resolution_binding_projections", "expected_binding_projection_count", "reference_semantic_key, output_frontier_key, projection_kind", 3, 1),
            qualified_seeded_routes => ("qualified_seeded_routes", "resolution_qualified_seeded_routes", "expected_qualified_seeded_route_count", "reference_semantic_key, precedence_ordinal, qualifier_frontier_key, lookup_semantic_key, namespace, projection_output_frontier_key, projection_kind, coarse_gap_reason_semantic_key", 8, 2),
            declaration_type_properties => ("declaration_type_properties", "resolution_declaration_type_properties", "expected_declaration_type_property_count", "definition_semantic_key, declaration_role, frontier_key", 3, 2),
            declaration_visibility_properties => ("declaration_visibility_properties", "resolution_declaration_visibility_properties", "expected_declaration_visibility_property_count", "definition_semantic_key, visibility", 2, 1),
            member_scope_properties => ("member_scope_properties", "resolution_member_scope_properties", "expected_member_scope_property_count", "definition_semantic_key, scope_head_node_key", 2, 1),
            member_owner_properties => ("member_owner_properties", "resolution_member_owner_properties", "expected_member_owner_property_count", "definition_semantic_key, owner_definition_semantic_key, owner_scope_head_node_key, member_kind, member_access, qualifier_compatibility", 6, 6),
            deferred_member_owner_properties => ("deferred_member_owner_properties", "resolution_deferred_member_owner_properties", "expected_deferred_member_owner_property_count", "definition_semantic_key, owner_frontier_key, member_kind, member_access, qualifier_compatibility", 5, 1),
            declared_type_relations => ("declared_type_relations", "resolution_declared_type_relations", "expected_declared_type_relation_count", "relation_semantic_key, subject_frontier_key, relation_kind, target_reference_semantic_key, target_frontier_key", 5, 1),
            relation_members => ("relation_members", "resolution_relation_members", "expected_relation_member_count", "relation_semantic_key, position, definition_semantic_key, member_kind", 4, 2),
            construction_requirement_properties => ("construction_requirement_properties", "resolution_construction_requirement_properties", "expected_construction_requirement_property_count", "definition_semantic_key, requirement_kind, required_owner_definition_semantic_key", 3, 3),
            supertype_properties => ("supertype_properties", "resolution_supertype_properties", "expected_supertype_property_count", "definition_semantic_key, supertype_kind, reference_semantic_key, frontier_key", 4, 4),
            definition_property_gaps => ("definition_property_gaps", "resolution_definition_property_gaps", "expected_definition_property_gap_count", "definition_semantic_key, reason_semantic_key, frontier_key, source_site, gap_kind", 5, 3),
            call_applicability_obligations => ("call_applicability_obligations", "resolution_call_applicability_obligations", "expected_call_applicability_obligation_count", "call_semantic_key, callee_reference_semantic_key, receiver_frontier_key, result_frontier_key, explicit_type_argument_count, applicability_reason_semantic_key, completion_kind, expected_argument_count, expected_completion_reason_count", 9, 1),
            call_applicability_arguments => ("call_applicability_arguments", "resolution_call_applicability_arguments", "expected_call_applicability_argument_count", "call_semantic_key, position, frontier_key", 3, 2),
            call_applicability_completion_reasons => ("call_applicability_completion_reasons", "resolution_call_applicability_completion_reasons", "expected_call_applicability_completion_reason_count", "call_semantic_key, position, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 2),
            engine_rule_eligibilities => ("engine_rule_eligibilities", "resolution_engine_rule_eligibilities", "expected_engine_rule_eligibility_count", "call_semantic_key, rule_kind", 2, 2),
            callable_signature_properties => ("callable_signature_properties", "resolution_callable_signature_properties", "expected_callable_signature_property_count", "definition_semantic_key, type_parameter_count, completion_kind, expected_parameter_count, expected_completion_reason_count", 5, 1),
            callable_signature_parameters => ("callable_signature_parameters", "resolution_callable_signature_parameters", "expected_callable_signature_parameter_count", "callable_definition_semantic_key, position, parameter_definition_semantic_key, frontier_key, repeated", 5, 2),
            callable_signature_completion_reasons => ("callable_signature_completion_reasons", "resolution_callable_signature_completion_reasons", "expected_callable_signature_completion_reason_count", "definition_semantic_key, position, reason_kind, cyclic_path_key, semantic_key, boundary_status", 6, 2),
            declared_root_routes => ("declared_root_routes", "resolution_declared_root_routes", "expected_declared_root_route_count", "root_scope_node_key, position, segment_semantic_key", 3, 2),
        }
    };
}

macro_rules! define_bundle_rows {
    ($($field:ident => ($name:literal, $table:literal, $count_column:literal, $columns:literal, $arity:literal, $key_arity:literal),)*) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub(super) struct PreparedResolutionBundleRows {
            $(pub(super) $field: Vec<PreparedResolutionRow>,)*
        }

        impl PreparedResolutionBundleRows {
            fn family_specs() -> [ResolutionFamilySpec; RESOLUTION_FAMILY_COUNT] {
                [$(ResolutionFamilySpec {
                    name: $name,
                    arity: $arity,
                    key_arity: $key_arity,
                },)*]
            }

            fn families(&self) -> [&[PreparedResolutionRow]; RESOLUTION_FAMILY_COUNT] {
                [$(&self.$field,)*]
            }

            fn families_mut(
                &mut self,
            ) -> [&mut Vec<PreparedResolutionRow>; RESOLUTION_FAMILY_COUNT] {
                [$(&mut self.$field,)*]
            }
        }
    };
}

resolution_bundle_families!(define_bundle_rows);

macro_rules! define_family_count {
    ($($field:ident => ($name:literal, $table:literal, $count_column:literal, $columns:literal, $arity:literal, $key_arity:literal),)*) => {
        const RESOLUTION_FAMILY_COUNT: usize = [$($name,)*].len();
    };
}
resolution_bundle_families!(define_family_count);

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
            let Some(canonical) = cancellable_row_sort(std::mem::take(rows), spec, cancellation)
            else {
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

    fn counts(&self) -> [usize; RESOLUTION_FAMILY_COUNT] {
        self.families().map(<[PreparedResolutionRow]>::len)
    }

    fn canonical_digest(
        &self,
        semantic_language: Language,
        producer_epoch: &str,
        family_counts: &[usize; RESOLUTION_FAMILY_COUNT],
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

fn cancellable_row_sort(
    rows: Vec<PreparedResolutionRow>,
    spec: ResolutionFamilySpec,
    cancellation: &CancellationToken,
) -> Option<Vec<PreparedResolutionRow>> {
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
                        && prepared_row_order(
                            source[left].as_ref().expect("unmerged left row"),
                            source[right].as_ref().expect("unmerged right row"),
                            spec.key_arity,
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

/// Producer vocabulary for prepared content; no active database epoch is installed.
const fn resolution_bundle_epoch(language: Language) -> &'static str {
    match language {
        Language::Java => "resolution-bundle-java-v11",
        Language::Go => "resolution-bundle-go-v12",
        Language::Cpp => "resolution-bundle-cpp-v7",
        Language::JavaScript => "resolution-bundle-javascript-v6",
        Language::TypeScript => "resolution-bundle-typescript-v6",
        Language::Python => "resolution-bundle-python-v6",
        Language::Rust => "resolution-bundle-rust-v38",
        Language::Php => "resolution-bundle-php-v6",
        Language::Scala => "resolution-bundle-scala-v6",
        Language::CSharp => "resolution-bundle-csharp-v6",
        Language::Ruby => "resolution-bundle-ruby-v6",
        Language::Kotlin => "resolution-bundle-kotlin-v6",
        Language::None => panic!("a resolution bundle needs an analyzable language"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Immutable prepared content with storage-local identities and canonical rows.
///
/// This value proves preparation completed. It does not prove database publication
/// or selected-workspace readiness. Construction is only through
/// [`super::prepare_resolution_bundle`].
pub struct PreparedResolutionBundle {
    semantic_language: Language,
    producer_epoch: &'static str,
    interior_digest: [u8; 32],
    family_counts: [usize; RESOLUTION_FAMILY_COUNT],
    logical_rows: usize,
    payload_bytes: usize,
    rows: PreparedResolutionBundleRows,
}

impl PreparedResolutionBundle {
    pub(super) fn new(
        semantic_language: Language,
        mut rows: PreparedResolutionBundleRows,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        assert_ne!(semantic_language, Language::None);
        if !rows.canonicalize(cancellation) {
            return None;
        }
        let producer_epoch = resolution_bundle_epoch(semantic_language);
        let family_counts = rows.counts();
        let interior_digest = rows.canonical_digest(
            semantic_language,
            producer_epoch,
            &family_counts,
            cancellation,
        )?;
        let logical_rows = family_counts
            .into_iter()
            .fold(1usize, usize::saturating_add);
        let payload_bytes = rows.payload_bytes(semantic_language, producer_epoch, cancellation)?;
        Some(Self {
            semantic_language,
            producer_epoch,
            interior_digest,
            family_counts,
            logical_rows,
            payload_bytes,
            rows,
        })
    }

    pub const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    /// Content producer vocabulary; not an installed database epoch.
    pub const fn producer_epoch(&self) -> &'static str {
        self.producer_epoch
    }

    /// Canonical digest of language, producer vocabulary, and all named row families.
    pub const fn interior_digest(&self) -> [u8; 32] {
        self.interior_digest
    }

    /// Every prepared row plus one manifest row.
    pub const fn logical_rows(&self) -> usize {
        self.logical_rows
    }

    /// Logical text and digest payload bytes, not retained heap or SQL file size.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Every row family's canonical name and complete count, including zeroes.
    pub fn family_counts(&self) -> impl ExactSizeIterator<Item = (&'static str, usize)> + '_ {
        PreparedResolutionBundleRows::family_specs()
            .into_iter()
            .zip(self.family_counts.iter().copied())
            .map(|(spec, count)| (spec.name, count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashSet;
    fn semantic_row(key: i64, byte: u8) -> PreparedResolutionRow {
        PreparedResolutionRow::new(vec![
            key.into(),
            "shared".into(),
            PreparedResolutionValue::Digest([byte; 32]),
        ])
    }

    fn sample_rows(extra_semantic: bool) -> PreparedResolutionBundleRows {
        let mut rows = PreparedResolutionBundleRows::default();
        rows.semantic_terms.push(semantic_row(0, 1));
        if extra_semantic {
            rows.semantic_terms.push(semantic_row(1, 2));
        }
        rows
    }

    fn bundle(language: Language, rows: PreparedResolutionBundleRows) -> PreparedResolutionBundle {
        PreparedResolutionBundle::new(language, rows, &CancellationToken::default())
            .expect("uncancelled bundle construction")
    }

    #[test]
    fn bundle_digest_is_order_independent_and_covers_every_named_family() {
        let first = bundle(Language::Java, sample_rows(true));
        let mut reordered_rows = sample_rows(true);
        reordered_rows.semantic_terms.reverse();
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
        assert_eq!(family_digests.len(), RESOLUTION_FAMILY_COUNT);
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
            empty.payload_bytes + "shared".len() + 32
        );
    }

    #[test]
    fn bundle_construction_polls_cancellation_during_canonicalization() {
        let mut rows = PreparedResolutionBundleRows::default();
        for key in 0..1_000 {
            rows.semantic_terms.push(semantic_row(key, 1));
        }
        let cancellation = CancellationToken::cancel_after_checks_for_test(20);
        assert!(PreparedResolutionBundle::new(Language::Java, rows, &cancellation).is_none());
        assert!(cancellation.is_cancelled());
    }

    #[test]
    #[should_panic(expected = "semantic_terms rows repeat a SQL primary key")]
    fn bundle_rejects_repeated_sql_primary_keys() {
        let mut rows = sample_rows(false);
        rows.semantic_terms.push(semantic_row(0, 2));
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
}
