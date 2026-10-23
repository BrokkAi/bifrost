//! Persistence and accounting for declaration visibility and exact source bridges.
//!
//! Visibility is keyed by the canonical source declaration identity. Native
//! declaration sites and display metadata links remain separate bridges: a
//! source declaration can have several native sites and several projections,
//! and neither projection is allowed to become a second visibility authority.

use std::collections::HashSet;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceDeclarationVisibilityFact,
};

use rusqlite::{Transaction, params};

use crate::CancellationToken;

use super::{Result, check_cancelled};

/// The source declaration visibility family is independently versioned from
/// the common source-facts manifest.
pub(super) const SOURCE_DECLARATION_VISIBILITY_VERSION: i64 =
    brokk_bifrost_core::analyzer::source_facts::SOURCE_DECLARATION_VISIBILITY_VERSION;

/// Return the logical rows and textual payload owned by the optional source
/// declaration visibility family. Common source publication accounts for the
/// native and metadata bridges independently of this optional family.
pub(super) fn source_declaration_visibility_cost(
    facts: &ParsedSourceFacts,
    metadata_links: &[(SourceDeclarationId, i64, i64)],
) -> (usize, usize) {
    validate_metadata_links(facts, metadata_links);
    let Some(visibilities) = facts.declaration_visibilities.as_ref() else {
        return (0, 0);
    };

    validate_inputs(facts, visibilities);
    (
        1usize.saturating_add(visibilities.len()),
        visibilities
            .iter()
            .map(|fact| fact.visibility.label().len())
            .fold(0usize, usize::saturating_add),
    )
}

/// Insert exact metadata links independently of any language visibility family.
pub(super) fn insert_source_declaration_metadata_bridges_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    metadata_links: &[(SourceDeclarationId, i64, i64)],
    cancellation: &CancellationToken,
) -> Result<()> {
    validate_metadata_links(facts, metadata_links);
    let mut metadata_bridge_rows = tx.prepare_cached(
        "INSERT INTO source_declaration_metadata_bridges(
           blob_id, declaration_id, unit_key, metadata_ordinal
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for &(declaration, unit_key, metadata_ordinal) in metadata_links {
        check_cancelled(cancellation)?;
        metadata_bridge_rows.execute(params![
            blob_id,
            i64::from(declaration.get()),
            unit_key,
            metadata_ordinal,
        ])?;
    }
    drop(metadata_bridge_rows);
    Ok(())
}

/// Insert one complete source declaration visibility family while the common
/// source manifest is still building. The common source seal follows this
/// function, so all family rows are covered by the same transaction.
pub(super) fn insert_source_declaration_visibility_facts_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    metadata_links: &[(SourceDeclarationId, i64, i64)],
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(visibilities) = facts.declaration_visibilities.as_ref() else {
        return Ok(());
    };

    validate_inputs(facts, visibilities);
    check_cancelled(cancellation)?;

    let mut visibility_rows = tx.prepare_cached(
        "INSERT INTO source_declaration_visibilities(
           blob_id, declaration_id, visibility
         ) VALUES(?1, ?2, ?3)",
    )?;
    for fact in visibilities {
        check_cancelled(cancellation)?;
        visibility_rows.execute(params![
            blob_id,
            i64::from(fact.declaration.get()),
            fact.visibility.label(),
        ])?;
    }
    drop(visibility_rows);

    check_cancelled(cancellation)?;
    tx.execute(
        "INSERT INTO source_declaration_visibility_manifests(
           blob_id, facts_version, visibility_count, native_bridge_count,
           metadata_bridge_count
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            blob_id,
            SOURCE_DECLARATION_VISIBILITY_VERSION,
            super::usize_to_i64(visibilities.len())?,
            super::usize_to_i64(facts.native_declaration_sources.len())?,
            super::usize_to_i64(metadata_links.len())?,
        ],
    )?;
    Ok(())
}

/// Publish exact native/source identity independently of optional visibility.
pub(super) fn insert_source_native_declaration_bridges_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    validate_native_declaration_bridges(facts);
    check_cancelled(cancellation)?;
    let mut rows = tx.prepare_cached(
        "INSERT INTO source_native_declaration_bridges(
           blob_id, source_site, declaration_id
         ) VALUES(?1, ?2, ?3)",
    )?;
    for &(source_site, declaration) in &facts.native_declaration_sources {
        check_cancelled(cancellation)?;
        rows.execute(params![
            blob_id,
            i64::from(source_site.get()),
            i64::from(declaration.get()),
        ])?;
    }
    Ok(())
}

fn validate_inputs(facts: &ParsedSourceFacts, visibilities: &[SourceDeclarationVisibilityFact]) {
    let declaration_count = facts.occurrences.declaration_count();
    let mut visibility_declarations = HashSet::with_capacity(visibilities.len());
    for fact in visibilities {
        assert!(
            fact.declaration.index() < declaration_count,
            "source declaration visibility points outside declaration rows"
        );
        assert!(
            visibility_declarations.insert(fact.declaration),
            "source declaration visibility has duplicate declaration {:?}",
            fact.declaration
        );
    }
}

pub(super) fn validate_native_declaration_bridges(facts: &ParsedSourceFacts) {
    let declaration_count = facts.occurrences.declaration_count();
    let mut native_sites = HashSet::with_capacity(facts.native_declaration_sources.len());
    for &(source_site, declaration) in &facts.native_declaration_sources {
        assert!(
            native_sites.insert(source_site),
            "source native declaration bridge has duplicate source site {:?}",
            source_site
        );
        assert!(
            declaration.index() < declaration_count,
            "source native declaration bridge points outside declaration rows"
        );
    }
}

fn validate_metadata_links(
    facts: &ParsedSourceFacts,
    metadata_links: &[(SourceDeclarationId, i64, i64)],
) {
    let declaration_count = facts.occurrences.declaration_count();
    let mut metadata_bridges = HashSet::with_capacity(metadata_links.len());
    for &(declaration, unit_key, metadata_ordinal) in metadata_links {
        assert!(
            declaration.index() < declaration_count,
            "source declaration metadata bridge points outside declaration rows"
        );
        assert!(
            unit_key >= 0,
            "source declaration metadata bridge has a negative unit key"
        );
        assert!(
            metadata_ordinal >= 0,
            "source declaration metadata bridge has a negative metadata ordinal"
        );
        assert!(
            metadata_bridges.insert((declaration, unit_key, metadata_ordinal)),
            "source declaration metadata bridge has duplicate link {:?}",
            (declaration, unit_key, metadata_ordinal)
        );
    }
}
