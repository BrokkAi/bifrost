//! The published catalog of row relations a policy may address.
//!
//! An agent authoring a relational policy needs to know which relations exist,
//! which columns they carry, which columns are safe to join on, and which
//! expansions lead where. That information already exists inside the analyzer's
//! row registry and this module's expansion table; this catalog is the one
//! serializable projection of it, so the answer an agent reads is the answer the
//! validator enforces.
//!
//! The catalog is data, not prose: it is deterministic, versioned, and carries
//! no evaluation state.

use brokk_bifrost_rql::structural::search::{
    ALL_DETAILED_CODE_QUERY_DOMAINS, DetailedCodeQueryDomain,
};
use brokk_bifrost_rql::structural::{CodeQueryEnumDomain, CodeQueryRowScalarType};
use serde::Serialize;

use super::ir::{ALL_ROW_EXPANSION_STEPS, expansion_result_domain};

/// The versioned format string of the relation-schema catalog. Consumers pin
/// this exact value; a shape change bumps the version.
pub const RELATION_SCHEMA_FORMAT: &str = "bifrost_relation_schema/v1";

/// Every row relation a relational policy may bind, with its columns and the
/// expansions admitted from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationSchemaCatalog {
    pub format: &'static str,
    pub domains: Vec<RelationDomainSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationDomainSchema {
    /// The registry label, which is also the name used in diagnostics.
    pub domain: &'static str,
    pub fields: Vec<RelationFieldSchema>,
    pub expansions: Vec<RelationExpansionSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationFieldSchema {
    pub name: &'static str,
    pub scalar_type: &'static str,
    /// Whether the registry may leave this field absent, which is also the only
    /// condition under which a null test over it is admitted.
    pub nullable: bool,
    /// Whether joining on this column correlates the same entity on both sides.
    ///
    /// Conservative on purpose: only identity-bearing scalars qualify. A
    /// `String` name or an enum label may be equal across unrelated rows, so a
    /// join on it is a filter, not a correlation.
    pub stable_join_key: bool,
    /// Every value a `constrained_enum` column can hold, in the producing
    /// vocabulary's declaration order. This is the same table the validator
    /// checks a literal against (issue #2515), so an author reading the catalog
    /// reads the rule that will be enforced.
    ///
    /// Absent for every other scalar type, and for the rare enum column whose
    /// producing vocabulary the registry marks as not enumerable, where
    /// `unenumerable_reason` states why instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unenumerable_reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationExpansionSchema {
    pub step: &'static str,
    pub result_domain: &'static str,
}

/// Build the catalog. Deterministic: domains and expansions are ordered by
/// label, fields keep their registry declaration order.
pub fn relation_schema_catalog() -> RelationSchemaCatalog {
    let mut domains = ALL_DETAILED_CODE_QUERY_DOMAINS
        .iter()
        .map(|domain| RelationDomainSchema {
            domain: domain.label(),
            fields: domain
                .row_fields()
                .iter()
                .map(|field| RelationFieldSchema {
                    name: field.name,
                    scalar_type: scalar_type_label(field.scalar_type),
                    nullable: field.nullable,
                    stable_join_key: is_stable_join_key(field.scalar_type),
                    values: match field.value_domain {
                        Some(CodeQueryEnumDomain::Labels(labels)) => Some(labels),
                        Some(CodeQueryEnumDomain::Unenumerable(_)) | None => None,
                    },
                    unenumerable_reason: match field.value_domain {
                        Some(CodeQueryEnumDomain::Unenumerable(reason)) => Some(reason),
                        Some(CodeQueryEnumDomain::Labels(_)) | None => None,
                    },
                })
                .collect(),
            expansions: admitted_expansions(*domain),
        })
        .collect::<Vec<_>>();
    domains.sort_by_key(|domain| domain.domain);
    RelationSchemaCatalog {
        format: RELATION_SCHEMA_FORMAT,
        domains,
    }
}

/// The expansions the validator admits from one domain, ordered by step label.
pub fn admitted_expansions(domain: DetailedCodeQueryDomain) -> Vec<RelationExpansionSchema> {
    let mut expansions = ALL_ROW_EXPANSION_STEPS
        .iter()
        .filter_map(|step| {
            expansion_result_domain(domain, *step).map(|result| RelationExpansionSchema {
                step: step.label(),
                result_domain: result.label(),
            })
        })
        .collect::<Vec<_>>();
    expansions.sort_by_key(|expansion| expansion.step);
    expansions
}

const fn scalar_type_label(scalar_type: CodeQueryRowScalarType) -> &'static str {
    match scalar_type {
        CodeQueryRowScalarType::StableId => "stable_id",
        CodeQueryRowScalarType::String => "string",
        CodeQueryRowScalarType::Integer => "integer",
        CodeQueryRowScalarType::Boolean => "boolean",
        CodeQueryRowScalarType::ConstrainedEnum => "constrained_enum",
        CodeQueryRowScalarType::DeclarationIdentity => "declaration_identity",
    }
}

const fn is_stable_join_key(scalar_type: CodeQueryRowScalarType) -> bool {
    matches!(
        scalar_type,
        CodeQueryRowScalarType::StableId | CodeQueryRowScalarType::DeclarationIdentity
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_covers_every_domain_the_validator_admits() {
        let catalog = relation_schema_catalog();
        assert_eq!(catalog.format, RELATION_SCHEMA_FORMAT);
        assert_eq!(catalog.domains.len(), ALL_DETAILED_CODE_QUERY_DOMAINS.len());
        for domain in ALL_DETAILED_CODE_QUERY_DOMAINS {
            let entry = catalog
                .domains
                .iter()
                .find(|entry| entry.domain == domain.label())
                .unwrap_or_else(|| panic!("domain `{}` is missing", domain.label()));
            assert_eq!(entry.fields.len(), domain.row_fields().len());
        }
    }

    /// Every expansion the validator admits must be published, and nothing
    /// else: the catalog and the validator read the same table.
    #[test]
    fn published_expansions_are_exactly_the_admitted_ones() {
        let catalog = relation_schema_catalog();
        let mut published = 0_usize;
        for entry in &catalog.domains {
            published += entry.expansions.len();
        }
        let admitted = ALL_DETAILED_CODE_QUERY_DOMAINS
            .iter()
            .flat_map(|domain| {
                ALL_ROW_EXPANSION_STEPS
                    .iter()
                    .filter(move |step| expansion_result_domain(*domain, **step).is_some())
            })
            .count();
        assert_eq!(published, admitted);
        let occurrence = catalog
            .domains
            .iter()
            .find(|entry| entry.domain == DetailedCodeQueryDomain::Occurrence.label())
            .expect("the occurrence domain is published");
        assert!(
            occurrence
                .expansions
                .iter()
                .any(|expansion| expansion.step == "member-selection"),
            "{:?}",
            occurrence.expansions
        );
    }

    #[test]
    fn only_identity_scalars_are_conservative_join_keys() {
        let catalog = relation_schema_catalog();
        for entry in &catalog.domains {
            for field in &entry.fields {
                assert_eq!(
                    field.stable_join_key,
                    matches!(field.scalar_type, "stable_id" | "declaration_identity"),
                    "{}.{}",
                    entry.domain,
                    field.name
                );
            }
        }
    }

    #[test]
    fn serialization_is_byte_deterministic() {
        let first = serde_json::to_string(&relation_schema_catalog()).expect("catalog serializes");
        let second = serde_json::to_string(&relation_schema_catalog()).expect("catalog serializes");
        assert_eq!(first, second);
        let mut labels = relation_schema_catalog()
            .domains
            .iter()
            .map(|domain| domain.domain)
            .collect::<Vec<_>>();
        let published = labels.clone();
        labels.sort_unstable();
        assert_eq!(labels, published, "domains are published in label order");
    }
}
