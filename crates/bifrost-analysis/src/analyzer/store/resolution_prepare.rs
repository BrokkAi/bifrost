//! Lower one already-built resolution artifact into storage-local bundle rows.
//!
//! This module does no parsing and no selected-workspace work. It translates
//! the combined lowering/catalog handoff while the source artifact is still
//! borrowed, polls cancellation throughout, and finishes all allocation and
//! canonicalization before the writer actor is entered.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionCallableReceiverOrigin, ResolutionGapKind,
    ResolutionNamespace, ResolutionSiteKind, ResolutionTypeSlotRole, ResolutionTypeTransferKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    DeclaredVisibility, ResolutionCompletionReasonKind,
};

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingNodeId, BindingNodeKind, LoweredBindingProjection, LoweredCallApplicabilityObligation,
    LoweredCallableSignatureProperty, LoweredCoverageGap, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDeferredMemberOwner, LoweredDefinitionPropertyGap,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredQualifiedSeededRoute,
    LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole, LoweredSemanticSite,
    LoweredSupertypeProperty, LoweredTypedFrontier, LoweringCoverageFrontier, LoweringGapOrigin,
    PartialPath, ResolutionCompletion, ResolutionIdentityCatalog, ResolutionIncompleteReason,
    ResolutionSemanticIdentitySpace, SemanticId, TypeTransferValueTransform,
};
use crate::hash::{HashMap, HashSet};

use super::resolution::{
    PreparedResolutionBundle, PreparedResolutionBundleRows, PreparedResolutionRow,
    PreparedResolutionValue, TypedFactRelation,
};

/// Lane LD's throwaway loader for the milestone 5 draft schema. It is a child
/// module so that it can reuse `ResolutionLocalKeys` rather than assign a
/// second set of dense per-blob keys.
#[cfg(test)]
mod schema_loader;

/// The `resolution_paths` and `resolution_identities` recipe encodings, shared
/// by the writer (`store/resolution.rs`), the reader
/// (`store/resolution_lexical.rs`) and the measurement loader above.
///
/// It is a child module of `resolution_prepare` for the same reason
/// `schema_loader` is: it needs `ResolutionLocalKeys`, the producer's own dense
/// per-blob key assignment, and that type is private to this module. Its
/// natural home is `store/resolution_rows.rs`, which needs one line in
/// `store/mod.rs`; that file is integrator-only for this lane, so the exact
/// diff is in the lane document instead.
pub(crate) mod resolution_rows;

pub(crate) mod authority_rows;
pub(crate) mod rust_authority;
/// The typed-fact rows of milestone 5's draft section 6 (milestone 6 port
/// block 4, lane TF). A child module of `resolution_prepare` for the same
/// reason `resolution_rows` is: it needs `ResolutionLocalKeys`.
pub(crate) mod typed_rows;

pub(crate) enum ResolutionInteriorPreparation {
    Prepared(Box<PreparedResolutionBundle>),
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SemanticKey(i64);

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedNodeCoordinate {
    local_key: PreparedResolutionValue,
    boundary_key: PreparedResolutionValue,
}

impl PreparedNodeCoordinate {
    const fn absent() -> Self {
        Self {
            local_key: PreparedResolutionValue::Null,
            boundary_key: PreparedResolutionValue::Null,
        }
    }
}

/// The storage-local key of every identity a lowered artifact holds.
///
/// A node's, a path's and a stack variable's key **is** its catalog position,
/// and a local runtime id carries that position in the clear
/// (`ResolutionIdentityKind::Local`), so those three need no map: the id is
/// the answer. What `new` does for them is assert the correspondence once per
/// catalog, which is the one place a lowering that numbered its artifact
/// wrongly would be caught.
///
/// The semantic catalog is the exception and keeps its map. It holds both a
/// blob's own identities and the shared names it mentions, and a shared name's
/// id is its `resolution_identities` id rather than a position, so the only
/// thing that can say which position a shared semantic occupies is the
/// catalog.
struct ResolutionLocalKeys {
    semantics: HashMap<SemanticId, SemanticKey>,
}

impl ResolutionLocalKeys {
    fn new(
        lowered: &LoweredResolutionFactsWithIdentityCatalog,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let identities = lowered.identities();
        let mut semantics = HashMap::default();
        for (index, (mounted, _)) in identities.semantics().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert!(
                semantics
                    .insert(*mounted, SemanticKey(dense_key(index)))
                    .is_none(),
                "semantic catalog must be a bijection"
            );
        }
        for (index, (mounted, _)) in identities.nodes().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert_carried_position(mounted.local_key(), index, "node", mounted);
        }
        for (index, (mounted, _)) in identities.paths().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert_carried_position(mounted.local_key(), index, "path", mounted);
        }
        for (index, (mounted, _)) in identities.stack_variables().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert_carried_position(mounted.local_key(), index, "stack variable", mounted);
        }
        Some(Self { semantics })
    }

    fn semantic(&self, semantic: SemanticId) -> i64 {
        self.semantics
            .get(&semantic)
            .unwrap_or_else(|| panic!("semantic {semantic} is missing from the identity catalog"))
            .0
    }

    fn node(&self, node: BindingNodeId) -> i64 {
        carried_key(node.local_key(), "node", node)
    }

    fn node_coordinate(&self, node: BindingNodeId) -> PreparedNodeCoordinate {
        if node == BindingNodeId::universal_root() {
            PreparedNodeCoordinate {
                local_key: PreparedResolutionValue::Null,
                boundary_key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY.into(),
            }
        } else {
            PreparedNodeCoordinate {
                local_key: self.node(node).into(),
                boundary_key: PreparedResolutionValue::Null,
            }
        }
    }

    fn optional_node_coordinate(&self, node: Option<BindingNodeId>) -> PreparedNodeCoordinate {
        node.map_or_else(PreparedNodeCoordinate::absent, |node| {
            self.node_coordinate(node)
        })
    }

    fn path(&self, path: crate::analyzer::resolution::PartialPathId) -> i64 {
        carried_key(path.local_key(), "path", path)
    }

    fn variable(&self, variable: crate::analyzer::resolution::StackVariableId) -> i64 {
        carried_key(variable.local_key(), "stack variable", variable)
    }
}

/// The storage-local key one runtime id carries.
fn carried_key(local_key: Option<u32>, label: &str, id: impl std::fmt::Display) -> i64 {
    i64::from(
        local_key.unwrap_or_else(|| {
            panic!("{label} {id} belongs to no blob and has no storage-local key")
        }),
    )
}

/// That a catalog position is the key the id at that position carries.
fn assert_carried_position(
    local_key: Option<u32>,
    index: usize,
    label: &str,
    id: impl std::fmt::Display,
) {
    assert_eq!(
        carried_key(local_key, label, id),
        dense_key(index),
        "a {label} catalog position is the storage-local key its runtime id carries"
    );
}

fn catalog_identity_at<Mounted, Identity>(
    entries: &[(Mounted, Identity)],
    mounted: Mounted,
    key: i64,
    label: &str,
) -> Identity
where
    Mounted: Copy + std::fmt::Debug + Eq,
    Identity: Copy,
{
    let index = usize::try_from(key).expect("storage-local identity key cannot be negative");
    let &(catalog_mounted, identity) = entries
        .get(index)
        .unwrap_or_else(|| panic!("{label} key {key} is outside the identity catalog"));
    assert_eq!(
        catalog_mounted, mounted,
        "{label} key must index its mounted identity"
    );
    identity
}

macro_rules! row {
    ($($value:expr),* $(,)?) => {
        PreparedResolutionRow::new(vec![$(PreparedResolutionValue::from($value)),*])
    };
}

struct PreparedNodePayload {
    kind: Option<i64>,
    semantic_local_key: Option<i64>,
    semantic_shared_identity: Option<[u8; 32]>,
    target: PreparedNodeCoordinate,
}

fn prepare_node_payload(
    kind: Option<BindingNodeKind>,
    keys: &ResolutionLocalKeys,
    catalog: &ResolutionIdentityCatalog,
) -> PreparedNodePayload {
    let (kind, semantic, target) = match kind {
        None => (None, None, None),
        Some(BindingNodeKind::Root) => (Some(0), None, None),
        Some(BindingNodeKind::Scope) => (Some(1), None, None),
        Some(BindingNodeKind::PushSymbol(semantic)) => (Some(2), Some(semantic), None),
        Some(BindingNodeKind::PopSymbol(semantic)) => (Some(3), Some(semantic), None),
        Some(BindingNodeKind::PushScopedSymbol(semantic)) => (Some(4), Some(semantic), None),
        Some(BindingNodeKind::PopScopedSymbol(semantic)) => (Some(5), Some(semantic), None),
        Some(BindingNodeKind::DropScopes) => (Some(6), None, None),
        Some(BindingNodeKind::JumpToScope(target)) => (Some(7), None, Some(target)),
        Some(BindingNodeKind::Reference(semantic)) => (Some(8), Some(semantic), None),
        Some(BindingNodeKind::Definition(semantic)) => (Some(9), Some(semantic), None),
    };
    let (semantic_local_key, semantic_shared_identity) =
        semantic.map_or((None, None), |semantic| {
            let identity = catalog
                .semantic_identity(semantic)
                .expect("a node payload semantic belongs to the producer catalog");
            match identity.shared_name() {
                Some(name) => (None, Some(catalog.shared_name_digest(name))),
                None => (Some(keys.semantic(semantic)), None),
            }
        });
    PreparedNodePayload {
        kind,
        semantic_local_key,
        semantic_shared_identity,
        target: keys.optional_node_coordinate(target),
    }
}

// The catalog is construction-local; persisted identities answer individual
// provenance and reverse-identity questions without rebuilding it per request.
fn prepare_catalog_authority(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let catalog = lowered.identities();
    let import_provenance = lowered
        .common()
        .root_import_provenance
        .iter()
        .map(|row| (row.token, row))
        .collect::<HashMap<_, _>>();
    for &(semantic, identity) in catalog.semantics() {
        if cancellation.is_cancelled() {
            return false;
        }
        // A gap reason holds a runtime position but no catalog row (#3737).
        // Reasons sort after every other identity, so the rows written here
        // stay dense from zero.
        if !identity.has_catalog_row() {
            continue;
        }
        let (digest, shared) = match identity {
            crate::analyzer::resolution::ResolutionSemanticIdentity::GapReason(_) => {
                unreachable!("filtered above")
            }
            crate::analyzer::resolution::ResolutionSemanticIdentity::FragmentLocal(digest) => {
                (Some(digest), None)
            }
            crate::analyzer::resolution::ResolutionSemanticIdentity::Shared(name) => {
                (None, Some(catalog.shared_name_digest(name)))
            }
        };
        let provenance = import_provenance.get(&semantic);
        rows.semantic_catalog.push(row![
            keys.semantic(semantic),
            digest,
            shared,
            provenance.map(|row| row.source_site.get()),
            provenance.map(
                |row| i64::try_from(row.start_byte).expect("source offset fits SQLite integer")
            ),
            provenance
                .map(|row| i64::try_from(row.end_byte).expect("source offset fits SQLite integer")),
            provenance.map(|row| resolution_rows::import_route_kind_label(row.kind))
        ]);
    }
    for identity in &lowered.common().reference_lookup_identities {
        if cancellation.is_cancelled() {
            return false;
        }
        push_reference_lookup_identity(identity.reference, identity.lookup, catalog, keys, rows);
    }
    let kinds = lowered
        .lexical()
        .nodes()
        .iter()
        .copied()
        .collect::<HashMap<_, _>>();
    for &(node, identity) in catalog.nodes() {
        if cancellation.is_cancelled() {
            return false;
        }
        // Catalog-only boundary nodes have identity but no producer node row.
        let payload = prepare_node_payload(kinds.get(&node).copied(), keys, catalog);
        rows.node_catalog.push(row![
            keys.node(node),
            identity.digest(),
            catalog
                .source_scope_ordinals()
                .get(&node)
                .map(|scope| scope.get()),
            payload.kind,
            payload.semantic_local_key,
            payload.semantic_shared_identity,
            payload.target.local_key,
            payload.target.boundary_key
        ]);
    }
    let references = lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Reference)
        .map(|site| (site.semantic(), site.site()))
        .collect::<HashMap<_, _>>();
    let targets = lowered.common().declared_type_relations.iter()
        .filter(|relation| relation.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclaredTypeRelationKind::TraitImplementation)
        .filter_map(|relation| relation.target_reference.map(|target| (relation.relation, target)))
        .collect::<HashMap<_, _>>();
    let mut positions = HashMap::<_, u32>::default();
    for member in &lowered.common().relation_members {
        if cancellation.is_cancelled() {
            return false;
        }
        if let Some(site) = targets
            .get(&member.relation)
            .and_then(|target| references.get(target))
        {
            let position = positions
                .entry((member.definition, member.kind))
                .or_default();
            rows.contract_references.push(row![
                keys.semantic(member.definition),
                resolution_rows::code(
                    brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_MEMBER_KINDS,
                    member.kind
                ),
                *position,
                site.get()
            ]);
            *position += 1;
        }
    }
    true
}

pub(crate) fn prepare_resolution_bundle_with_unit_keys(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    unit_keys: Option<&HashMap<CodeUnit, i64>>,
    cancellation: &CancellationToken,
) -> ResolutionInteriorPreparation {
    prepare_resolution_bundle_rows(
        lowered,
        unit_keys,
        PreparedResolutionBundleRows::default(),
        cancellation,
    )
}

pub(crate) fn prepare_resolution_bundle_with_source_facts(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    unit_keys: &HashMap<CodeUnit, i64>,
    source: Option<&brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts>,
    cancellation: &CancellationToken,
) -> super::Result<ResolutionInteriorPreparation> {
    let mut rows = PreparedResolutionBundleRows::default();
    if lowered.lexical().language() == Language::Rust {
        let source = source.expect("parsed Rust publication has canonical source facts");
        match rust_authority::prepare(lowered, source, &mut rows, cancellation) {
            Ok(true) => {}
            Ok(false) => return Ok(ResolutionInteriorPreparation::Cancelled),
            Err(_) if cancellation.is_cancelled() => {
                return Ok(ResolutionInteriorPreparation::Cancelled);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(prepare_resolution_bundle_rows(
        lowered,
        Some(unit_keys),
        rows,
        cancellation,
    ))
}

fn prepare_resolution_bundle_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    unit_keys: Option<&HashMap<CodeUnit, i64>>,
    mut rows: PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> ResolutionInteriorPreparation {
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    let lexical = lowered.lexical();
    let typed = lowered.typed();
    assert_eq!(lexical.fragment(), typed.fragment());
    assert_eq!(lexical.fragment(), lowered.identities().fragment());
    assert_eq!(lexical.language(), typed.language());
    assert_ne!(lexical.language(), Language::None);
    let semantic_language = lexical.language();
    let Some(keys) = ResolutionLocalKeys::new(lowered, cancellation) else {
        return ResolutionInteriorPreparation::Cancelled;
    };
    if !prepare_catalog_authority(lowered, &keys, &mut rows, cancellation) {
        return ResolutionInteriorPreparation::Cancelled;
    }

    if !prepare_lookup_recipe_keys(lowered, &keys, cancellation) {
        return ResolutionInteriorPreparation::Cancelled;
    }
    if !prepare_lexical_rows(lowered, &keys, &mut rows, cancellation) {
        return ResolutionInteriorPreparation::Cancelled;
    }
    if !prepare_common_rows(lowered, &keys, unit_keys, &mut rows, cancellation)
        || !prepare_typed_rows(lowered, &keys, &mut rows, cancellation)
        || !prepare_typed_fact_lookups(lowered, &mut rows, cancellation)
        || cancellation.is_cancelled()
    {
        return ResolutionInteriorPreparation::Cancelled;
    }
    // Header rows are derived once per path and once per gap, so the same
    // distinct discovery shape is produced many times. The relation is the
    // distinct set.
    for family in [
        &mut rows.path_endpoint_headers,
        &mut rows.path_terminal_headers,
        &mut rows.reference_lookup_identities,
        &mut rows.typed_fact_lookups,
    ] {
        family.sort_unstable();
        family.dedup();
    }
    // Milestone 6's checkpoint (lane PK). The path rows and the store-wide
    // recipe rows are derived from the same lowering and the same dense keys as
    // every other family, but they are not a bundle family: they are neither
    // counted in the manifest nor hashed into the interior digest, so adding
    // them changes no existing row, column or digest.
    let path_rows =
        resolution_rows::prepare_path_rows(&keys, lowered.identities(), lexical.paths());
    let recipe_rows = resolution_rows::prepare_lookup_recipe_rows(lowered.identities());
    // Port block 2 (lane CM): `resolution_sites`, from the same lowered facts
    // `resolution_semantic_sites` is written from and with the same dense
    // keys. `prepare_lexical_rows` above has already asserted that a site's
    // number is its semantic's key and its node's key.
    let site_rows = resolution_rows::prepare_site_rows(&keys, lexical.semantics());
    // Milestone 6 port block 4 (lane TF), on the same terms: derived from the
    // same lowering and the same dense keys, counted in no manifest and hashed
    // into no interior digest.
    let typed_fact_rows = typed_rows::prepare_typed_rows(&keys, lowered.identities(), typed);
    // Milestone 6, port block 3 (lane GR): every coverage gap of the blob, as
    // `resolution_gaps` and one `resolution_gap_reasons` row per reason. Out of
    // the manifest and the interior digest for the same reason the path rows
    // are: a store this tree writes stays readable by the interiors that read
    // it before.
    let gap_rows = resolution_rows::prepare_gap_rows(&keys, lowered.identities(), lexical.gaps());
    let Some(bundle) = PreparedResolutionBundle::new(
        semantic_language,
        rows,
        path_rows,
        site_rows,
        typed_fact_rows,
        recipe_rows,
        gap_rows,
        lowered.identities().shared_names(),
        cancellation,
    ) else {
        return ResolutionInteriorPreparation::Cancelled;
    };
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    ResolutionInteriorPreparation::Prepared(Box::new(bundle))
}

fn prepare_common_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    unit_keys: Option<&HashMap<CodeUnit, i64>>,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let common = lowered.common();
    for fact in &common.package_references {
        if cancellation.is_cancelled() {
            return false;
        }
        if lowered.lexical().language() == Language::Go {
            // A Go package-reference path starts at the package scope, so the
            // path-based identity pass cannot associate its root terminal
            // with a reference node. Publish the same structured lookup here
            // as a blob-level candidate header; selected forward resolution
            // still confirms each candidate at its source site.
            push_shared_reference_lookup_identity(fact.lookup, lowered.identities(), keys, rows);
        }
        rows.package_references.push(row![
            keys.semantic(fact.token),
            keys.semantic(fact.domain),
            keys.semantic(fact.reference),
            fact.source_site.get(),
            keys.node(fact.root_scope),
            fact.namespace.label(),
            keys.semantic(fact.lookup),
        ]);
    }
    for fact in &common.package_members {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.package_members.push(row![
            keys.semantic(fact.token),
            keys.semantic(fact.definition),
            keys.semantic(fact.domain),
            fact.source_site.get(),
            keys.node(fact.root_scope),
            fact.namespace.label(),
            keys.semantic(fact.lookup),
        ]);
    }
    for fact in &common.go_package_imports {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.go_package_imports.push(row![
            keys.semantic(fact.definition),
            fact.source_site.get(),
            keys.node(fact.file_scope),
            keys.semantic(fact.spelling_choice),
            i64::try_from(fact.start_byte).expect("source offset fits SQLite integer"),
            i64::try_from(fact.end_byte).expect("source offset fits SQLite integer"),
            fact.kind.label(),
        ]);
    }
    for fact in &common.additional_definition_namespaces {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.additional_definition_namespaces.push(row![
            keys.semantic(fact.definition),
            fact.namespace.label(),
            fact.hoisting.label(),
        ]);
    }
    for fact in &common.definition_unit_crosswalks {
        if cancellation.is_cancelled() {
            return false;
        }
        let unit_key = unit_keys
            .and_then(|unit_keys| unit_keys.get(&fact.unit))
            .copied()
            .unwrap_or_else(|| {
                panic!(
                    "definition {:?} names parsed unit absent from combined blob preparation: {:?}",
                    fact.definition, fact.unit
                )
            });
        // The definition's own identity digest travels with the crosswalk.
        // It is fragment-local, so it does not belong in the workspace-wide
        // shared identity table, and the projection reader that wants it is
        // operation-free and cannot produce an interior.
        let identity = lowered
            .identities()
            .semantic_identity(fact.definition)
            .expect("a crosswalked definition names a catalog identity");
        assert_eq!(
            identity.space(),
            ResolutionSemanticIdentitySpace::FragmentLocal,
            "a definition identity is fragment-local"
        );
        rows.definition_unit_crosswalks.push(row![
            keys.semantic(fact.definition),
            unit_key,
            identity.fragment_local_digest()
        ]);
    }
    let identities = lowered.identities();
    for fact in &common.trait_implementations {
        if cancellation.is_cancelled() {
            return false;
        }
        // One route position per row, as the root-route family spells a module
        // path: positions 0..n-1 are the module segments the side writes and
        // the row at n closes the side with its head nominal name. The impl's
        // site and byte span ride every row, so the derivation places the impl
        // in its module and names it from whichever row it reached.
        let relation = keys.semantic(fact.relation);
        for (side, path) in [
            ("subject", &fact.subject),
            ("trait", &fact.implemented_trait),
        ] {
            for (position, segment) in path.segments.iter().enumerate() {
                rows.trait_implementations.push(row![
                    relation,
                    side,
                    usize_i64(position),
                    lookup_spelling(identities, *segment),
                    PreparedResolutionValue::Null,
                    i64::from(fact.impl_site),
                    usize_i64(fact.impl_start_byte),
                    usize_i64(fact.impl_end_byte),
                ]);
            }
            rows.trait_implementations.push(row![
                relation,
                side,
                usize_i64(path.segments.len()),
                PreparedResolutionValue::Null,
                lookup_spelling(identities, path.terminal),
                i64::from(fact.impl_site),
                usize_i64(fact.impl_start_byte),
                usize_i64(fact.impl_end_byte),
            ]);
        }
    }
    true
}

/// The text one lookup semantic spells, as the catalog recorded it.
fn lookup_spelling(identities: &ResolutionIdentityCatalog, semantic: SemanticId) -> &str {
    identities
        .lookup_recipe(semantic)
        .unwrap_or_else(|| panic!("a spelled path segment names a lookup recipe: {semantic:?}"))
        .spelling()
}

/// Give every lookup recipe its storage-local key, and hold that each one
/// speaks the artifact's semantic language.
///
/// This pass wrote a row until the name-mention relation was deleted. The
/// shared slice of the identity catalog is no longer a relation of its own: it
/// was `resolution_blob_identities`, "which blobs mention this name anywhere",
/// and once every typed read took its membership from
/// `resolution_typed_fact_lookups` nothing read it. The identities a reader
/// still needs are interned by the header families that name them.
fn prepare_lookup_recipe_keys(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    cancellation: &CancellationToken,
) -> bool {
    for (semantic, recipe) in lowered.identities().lookup_recipes() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert_eq!(
            recipe.semantic_language(),
            lowered.lexical().language().config_label(),
            "lookup recipe language must equal the artifact semantic language"
        );
        keys.semantic(*semantic);
    }
    true
}

fn prepare_lexical_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let lexical = lowered.lexical();
    let identities = lowered.identities();
    let mut sites_by_node = HashMap::default();
    let mut sites_by_semantic = HashMap::default();
    for site in lexical.semantics() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            sites_by_node.insert(site.node(), site).is_none(),
            "one lowered semantic site owns each semantic node"
        );
        assert!(
            sites_by_semantic
                .insert((site.semantic(), site.role()), site)
                .is_none(),
            "one semantic occupies one site in each role"
        );
        // The one number the schema's sites table is keyed by. The catalog
        // numbers a site's semantic and node with the site
        // (`ResolutionIdentityCatalogBuilder::finish`) and a local key is the
        // catalog position, so the row's site and its semantic key are the
        // same integer; milestone 6 reads one b-tree entry where three exist
        // today. Held here as well as at the catalog because this is the
        // boundary the reader inherits it across.
        let semantic_key = keys.semantic(site.semantic());
        let site_key = i64::from(site.site().get());
        assert_eq!(
            semantic_key, site_key,
            "a persisted site numbers its own semantic: {site:?}"
        );
        assert_eq!(
            keys.node(site.node()),
            site_key,
            "a persisted site numbers its own node: {site:?}"
        );
        rows.semantic_sites.push(row![
            site_key,
            site.namespace().label(),
            semantic_role_label(site.role()),
            semantic_key,
        ]);
    }

    let mut reference_gaps =
        HashMap::<BindingNodeId, BTreeMap<i64, &LoweredCoverageGap>>::default();
    let scope_ordinals = identities
        .source_scope_ordinals()
        .iter()
        .map(|(node, scope)| {
            (
                *node,
                usize::try_from(scope.get()).expect("source scope ordinal fits usize"),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut provenance = HashMap::default();
    for gap in lexical.gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        // Gap-reason provenance explains an unsupported semantic. An open
        // boundary is not a producer shortfall: its own evidence carries the
        // boundary status.
        //
        // `resolution_fragment_interiors_validate_gap_reason_provenance` paired
        // the provenance rows with the unsupported-semantic evidence in five
        // other families, because a separate table could drift from them. Both
        // sides are read from `lexical.gaps()` in this one pass now, so the
        // pairing is structural; what is left to check is that one reason
        // semantic has one provenance and that it is the blob's own identity.
        if gap.origin() != LoweringGapOrigin::ExternalPreludeBoundary {
            let value = (gap.site(), gap.origin());
            if let Some(previous) = provenance.insert(gap.reason_semantic(), value) {
                assert_eq!(previous, value, "one reason semantic has one provenance");
            }
            assert_eq!(
                identities
                    .semantic_identity(gap.reason_semantic())
                    .map(|identity| identity.space()),
                Some(ResolutionSemanticIdentitySpace::FragmentLocal),
                "a gap reason with provenance is the blob's own identity: {:?}",
                gap.reason_semantic()
            );
        }
        if let LoweringCoverageFrontier::Reference { semantic, node } = gap.frontier() {
            assert_eq!(
                sites_by_node.get(&node).map(|site| site.semantic()),
                Some(semantic),
                "reference gap must name its exact semantic node"
            );
            assert!(
                reference_gaps
                    .entry(node)
                    .or_default()
                    .insert(keys.semantic(gap.reason_semantic()), gap)
                    .is_none(),
                "one reference node cannot repeat a storage-local completion reason"
            );
        }
    }
    // The node relation is interior detail and is no longer persisted, but the
    // invariants it used to carry into the store are still the contract every
    // reader depends on, so they are asserted here, where the interior is
    // built, instead of in a publication trigger over rows nobody writes.
    let mut reference_nodes = HashSet::default();
    let mut sited_nodes = 0usize;
    for (node, kind) in lexical.nodes() {
        if cancellation.is_cancelled() {
            return false;
        }
        if matches!(kind, BindingNodeKind::Reference(_)) {
            reference_nodes.insert(*node);
        }
        // Every node the lowering emits occupies one catalog position; a
        // missing one panics here rather than reaching a reader as a key that
        // resolves to the wrong node.
        keys.node(*node);
        match kind {
            BindingNodeKind::Root => {
                panic!("content-owned source lowering cannot persist a universal root node")
            }
            BindingNodeKind::Scope => {
                scope_ordinals.get(node);
            }
            BindingNodeKind::PushSymbol(semantic)
            | BindingNodeKind::PopSymbol(semantic)
            | BindingNodeKind::PushScopedSymbol(semantic)
            | BindingNodeKind::PopScopedSymbol(semantic) => {
                keys.semantic(*semantic);
            }
            BindingNodeKind::DropScopes => {}
            BindingNodeKind::JumpToScope(scope) => {
                keys.node_coordinate(*scope);
            }
            BindingNodeKind::Reference(semantic) | BindingNodeKind::Definition(semantic) => {
                keys.semantic(*semantic);
                let site = sites_by_node
                    .get(node)
                    .expect("a reference or definition node has a semantic site");
                sited_nodes += 1;
                assert_eq!(
                    site.semantic(),
                    *semantic,
                    "a reference or definition node's semantic must match its source site"
                );
                assert_eq!(
                    site.role() == LoweredSemanticRole::Reference,
                    matches!(kind, BindingNodeKind::Reference(_)),
                    "a semantic site's role must match its node kind"
                );
                if matches!(kind, BindingNodeKind::Reference(_)) {
                    let metadata = site
                        .site_metadata()
                        .expect("every lowered reference node has source metadata");
                    assert_eq!(
                        metadata.namespace(),
                        site.namespace(),
                        "a reference site's metadata namespace must match its semantic site"
                    );
                    assert_eq!(
                        metadata.site(),
                        site.site(),
                        "a reference site's metadata must name its own source site"
                    );
                    // The callable-receiver origin was validated by a
                    // publication trigger over the reference-site rows; it is
                    // a property of one lowered site and belongs here.
                    assert!(
                        metadata.callable_receiver_origin().is_none_or(|origin| {
                            metadata.namespace() == ResolutionNamespace::Callable
                                && matches!(
                                    metadata.site_kind(),
                                    ResolutionSiteKind::CallableReference
                                        | ResolutionSiteKind::MemberReference
                                )
                                && metadata.unqualified()
                                    == (origin == ResolutionCallableReceiverOrigin::Implicit)
                        }),
                        "a callable receiver origin needs a callable reference site: {metadata:?}"
                    );
                    // `resolution_fragment_interiors_validate_reference_owners`
                    // proved that a known reference owner is a declaration of
                    // the same graph. Both relations it joined are interior
                    // detail now, and the lowered fragment holds the same fact.
                    if let Some(Some(owner)) = metadata.reference_owner() {
                        keys.semantic(owner);
                        let owner_site = sites_by_semantic
                            .get(&(owner, LoweredSemanticRole::Definition))
                            .expect("a known reference owner is a local declaration");
                        assert!(
                            matches!(
                                owner_site.namespace(),
                                ResolutionNamespace::Type
                                    | ResolutionNamespace::Callable
                                    | ResolutionNamespace::Constructor
                                    | ResolutionNamespace::Value
                            ),
                            "a reference owner declares a type, callable, constructor or value: {:?}",
                            owner_site.namespace()
                        );
                    }
                }
            }
        }
        reference_gaps.remove(node);
    }
    assert!(
        reference_gaps.is_empty(),
        "every reference gap must name a lowered reference node"
    );
    // Node to site was checked one node at a time above; this closes the other
    // direction, so no semantic site can name a node that is neither a
    // reference nor a definition.
    assert_eq!(
        sited_nodes,
        sites_by_node.len(),
        "every semantic site belongs to a reference or definition node"
    );

    for (path_id, path) in lexical.paths() {
        if cancellation.is_cancelled() {
            return false;
        }
        // Every path the lowering emits occupies one catalog position, which
        // is the key its root route is published under.
        let path_key = keys.path(*path_id);
        prepare_path_headers(path, identities, rows);
        prepare_reference_lookup_identity(path, &reference_nodes, identities, keys, rows);
        if lowered.lexical().language() == Language::Java {
            prepare_java_member_reference_lookup_identity(
                path,
                &reference_nodes,
                identities,
                keys,
                rows,
            );
        }
        prepare_root_route(
            path_key,
            path,
            sites_by_node.get(&path.start().node()).copied(),
            identities,
            rows,
        );
    }

    !cancellation.is_cancelled()
}

/// The shared identity a reference in this blob looks up through the crate
/// root, as a discovery header.
///
/// Reverse discovery asks which blobs could reference one identity. A root
/// path whose start is a reference node and whose end reaches the universal
/// root under three or more fixed symbols carries the lookup name in its last
/// fixed end symbol; a qualified route carries it in its source lookup. Both
/// answer the question without opening the blob.
fn prepare_reference_lookup_identity(
    path: &PartialPath,
    reference_nodes: &HashSet<BindingNodeId>,
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
) {
    if path.end().node() != BindingNodeId::universal_root()
        || path.end().symbols().fixed().len() < 3
        || !reference_nodes.contains(&path.start().node())
    {
        return;
    }
    let terminal = path
        .end()
        .symbols()
        .fixed()
        .last()
        .expect("a three-symbol stack has a last symbol")
        .symbol();
    push_shared_reference_lookup_identity(terminal, identities, keys, rows);
}

/// Java member references can end at a local type or receiver scope instead
/// of the universal root. Publish the shared-name header that selected
/// lookup_reference_sites seeks so those calls and fields remain candidate-
/// visible to Java inverse queries.
fn prepare_java_member_reference_lookup_identity(
    path: &PartialPath,
    reference_nodes: &HashSet<BindingNodeId>,
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
) {
    if !reference_nodes.contains(&path.start().node()) {
        return;
    }
    let Some(lead) = path.end().symbols().fixed().first() else {
        return;
    };
    push_shared_reference_lookup_identity(lead.symbol(), identities, keys, rows);
}

/// The tier-1 route one reference takes to the crate root.
///
/// Build-time crate derivation asks, for every member blob of a crate, which
/// references route through the crate root, under which module path, for which
/// name, and where in the file they sit. Answering that from path bodies would
/// mean joining path, reference-site and recipe relations across every member
/// blob, which is a cross-blob question about interior detail. One row per
/// route position answers it directly: positions `0..segments` spell the
/// module path, and the row at `segments` closes the route with the name it
/// demands and the reference site that demands it.
///
/// A route with an unnamed segment has no module path a crate can walk, so the
/// derivation discards it; that filter runs here instead, once per blob.
fn prepare_root_route(
    path_key: i64,
    path: &PartialPath,
    start_site: Option<&LoweredSemanticSite>,
    identities: &ResolutionIdentityCatalog,
    rows: &mut PreparedResolutionBundleRows,
) {
    if path.end().node() != BindingNodeId::universal_root() {
        return;
    }
    let fixed = path.end().symbols().fixed();
    if fixed.len() < 3 {
        return;
    }
    let Some(site) = start_site.filter(|site| site.role() == LoweredSemanticRole::Reference) else {
        return;
    };
    let Some(metadata) = site.site_metadata() else {
        return;
    };
    let Some(terminal) = identities.lookup_recipe(
        fixed
            .last()
            .expect("a three-symbol stack has a last symbol")
            .symbol(),
    ) else {
        return;
    };
    let segments = fixed[1..fixed.len() - 2]
        .iter()
        .map(|symbol| identities.lookup_recipe(symbol.symbol()))
        .collect::<Option<Vec<_>>>();
    let Some(segments) = segments else {
        return;
    };
    for (position, segment) in segments.iter().enumerate() {
        rows.root_route_segments.push(row![
            path_key,
            usize_i64(position),
            segment.spelling(),
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
        ]);
    }
    rows.root_route_segments.push(row![
        path_key,
        usize_i64(segments.len()),
        PreparedResolutionValue::Null,
        terminal.spelling(),
        i64::from(site.site().get()),
        usize_i64(metadata.start_byte()),
        usize_i64(metadata.end_byte()),
    ]);
}

fn push_shared_reference_lookup_identity(
    semantic: SemanticId,
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
) {
    push_reference_lookup_identity(semantic, semantic, identities, keys, rows);
}

fn push_reference_lookup_identity(
    reference: SemanticId,
    lookup: SemanticId,
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
) {
    let Some(identity) = identities.semantic_identity(lookup) else {
        return;
    };
    let Some(name) = identity.shared_name() else {
        return;
    };
    rows.reference_lookup_identities.push(row![
        keys.semantic(reference),
        identities.shared_name_digest(name)
    ]);
}

/// The tier-1 discovery headers of one universal-root-rooted partial path.
///
/// Candidate discovery asks which blobs could answer a boundary-rooted demand.
/// One row per distinct (direction, first-symbol identity, fixed symbol count,
/// open tail) answers that without opening any blob, and the terminal header
/// answers the root-import demand's last-symbol question the same way. Local
/// endpoints need no header: their demand already names one mount.
fn prepare_path_headers(
    path: &PartialPath,
    identities: &ResolutionIdentityCatalog,
    rows: &mut PreparedResolutionBundleRows,
) {
    let shared_digest = |semantic| {
        identities
            .semantic_identity(semantic)
            .and_then(crate::analyzer::resolution::ResolutionSemanticIdentity::shared_name)
            .map(|name| identities.shared_name_digest(name))
    };
    for (direction, endpoint) in [("forward", path.start()), ("reverse", path.end())] {
        if endpoint.node() != BindingNodeId::universal_root() {
            continue;
        }
        let fixed = endpoint.symbols().fixed();
        let open_tail = endpoint.symbols().tail().is_some();
        rows.path_endpoint_headers.push(row![
            direction,
            fixed
                .first()
                .and_then(|symbol| shared_digest(symbol.symbol())),
            usize_i64(fixed.len()),
            open_tail,
        ]);
        if let Some(terminal) = fixed.last()
            && let Some(digest) = shared_digest(terminal.symbol())
        {
            rows.path_terminal_headers
                .push(row![direction, digest, usize_i64(fixed.len())]);
        }
    }
}

fn prepare_typed_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let typed = lowered.typed();
    let reference_semantics = lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Reference)
        .map(LoweredSemanticSite::semantic)
        .collect::<HashSet<_>>();
    let definition_semantics = lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Definition)
        .map(LoweredSemanticSite::semantic)
        .collect::<HashSet<_>>();
    if !assert_typed_semantic_ownership(lowered, &reference_semantics, &definition_semantics)
        || !assert_typed_identity_spaces(lowered, cancellation)
        || !assert_declaration_visibility_coverage(lowered)
    {
        return false;
    }
    let mut frontier_roles = HashMap::default();
    for frontier in typed.frontiers() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            frontier_roles
                .insert(frontier.slot(), frontier.role())
                .is_none(),
            "one typed frontier per slot"
        );
        keys.semantic(frontier.slot());
    }
    let typed_slots = frontier_roles.keys().copied().collect::<HashSet<_>>();

    let mut synthetic_frontiers = BTreeMap::new();
    for gap in lowered.lexical().gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        let LoweringCoverageFrontier::Type { frontier } = gap.frontier() else {
            continue;
        };
        let frontier_key = keys.semantic(frontier);
        if typed_slots.contains(&frontier) {
            continue;
        }
        let identity = catalog_identity_at(
            lowered.identities().semantics(),
            frontier,
            frontier_key,
            "synthetic-frontier semantic catalog",
        );
        assert_eq!(
            identity.space(),
            ResolutionSemanticIdentitySpace::FragmentLocal,
            "a synthetic type frontier must remain fragment-local"
        );
        if let Some((previous_frontier, previous_site)) =
            synthetic_frontiers.insert(frontier_key, (frontier, gap.site()))
        {
            assert_eq!(previous_frontier, frontier);
            assert_eq!(
                previous_site,
                gap.site(),
                "one synthetic frontier has one source site"
            );
        }
    }
    for (frontier_key, _) in synthetic_frontiers {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            frontier_key >= 0,
            "a synthetic frontier occupies a catalog position"
        );
    }
    // The transfer-rule validators were publication triggers over the transfer
    // and frontier rows. Both families are interior detail now, and every term
    // they compared is a property of one lowered rule, so they run here.
    let mut type_identity_targets = HashSet::default();
    for transfer in typed.transfers() {
        if cancellation.is_cancelled() {
            return false;
        }
        let rule = transfer.rule();
        let source_role = frontier_roles.get(&transfer.source_slot()).copied();
        let target_role = frontier_roles.get(&rule.target_slot()).copied();
        let preserves_value = rule.value_transform() == TypeTransferValueTransform::Preserve
            && rule.reference_indirection_delta() == 0;
        match transfer.kind() {
            ResolutionTypeTransferKind::Initialization => assert!(
                matches!(
                    rule.value_transform(),
                    TypeTransferValueTransform::Preserve
                        | TypeTransferValueTransform::AddressableRuntimeOnly
                ) && rule.reference_indirection_delta() == 0
                    && rule.indirection_delta() == 0
                    && matches!(
                        source_role,
                        Some(
                            ResolutionTypeSlotRole::CallResult
                                | ResolutionTypeSlotRole::ExpressionValue
                        )
                    )
                    && target_role == Some(ResolutionTypeSlotRole::DeclaredValue),
                "initialization transfer has inconsistent roles or transform: {rule:?}"
            ),
            ResolutionTypeTransferKind::TypeIdentity | ResolutionTypeTransferKind::TypeUnion => {
                assert!(
                    preserves_value
                        && rule.indirection_delta() == 0
                        && source_role == Some(ResolutionTypeSlotRole::TargetTypeIdentity)
                        && target_role == Some(ResolutionTypeSlotRole::TargetTypeIdentity),
                    "type-identity transfer has inconsistent roles or transform: {rule:?}"
                );
                if transfer.kind() == ResolutionTypeTransferKind::TypeIdentity {
                    type_identity_targets.insert(rule.target_slot());
                }
            }
            ResolutionTypeTransferKind::AddressOf => assert!(
                rule.indirection_delta() == 1
                    && rule.reference_indirection_delta() == 0
                    && matches!(
                        rule.value_transform(),
                        TypeTransferValueTransform::AddressableOperandOnly
                            | TypeTransferValueTransform::RuntimeOnly
                    )
                    && matches!(
                        source_role,
                        Some(
                            ResolutionTypeSlotRole::CallResult
                                | ResolutionTypeSlotRole::ExpressionValue
                        )
                    )
                    && target_role == Some(ResolutionTypeSlotRole::ExpressionValue),
                "address-of transfer has inconsistent roles or transform: {rule:?}"
            ),
            ResolutionTypeTransferKind::Unwrap => assert!(
                preserves_value
                    && rule.indirection_delta() == -1
                    && matches!(
                        source_role,
                        Some(
                            ResolutionTypeSlotRole::CallResult
                                | ResolutionTypeSlotRole::ExpressionValue
                        )
                    )
                    && target_role == Some(ResolutionTypeSlotRole::CallResult),
                "unwrap transfer has inconsistent roles or transform: {rule:?}"
            ),
            _ => {}
        }
        if serialized_completion(rule.completion(), keys, cancellation).is_none() {
            return false;
        }
        keys.semantic(rule.semantic());
        keys.semantic(transfer.source_slot());
        keys.semantic(rule.target_slot());
    }

    // `resolution_fragment_interiors_validate_typed_producers_and_roles` also
    // proved that one frontier has one producer and that a projection's output
    // slot carries the role its kind implies.
    let mut projected_slots = HashSet::default();
    for projection in typed.projections() {
        if cancellation.is_cancelled() {
            return false;
        }
        keys.semantic(projection.reference());
        keys.semantic(projection.output_slot());
        assert_eq!(
            frontier_roles.get(&projection.output_slot()).copied(),
            Some(match projection.kind() {
                BindingProjectionKind::TargetTypeIdentity
                | BindingProjectionKind::TargetNominalTypeIdentity
                | BindingProjectionKind::TargetMemberOwnerType =>
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                BindingProjectionKind::TargetCallableResultType
                | BindingProjectionKind::TargetConstructorOwnerType =>
                    ResolutionTypeSlotRole::CallResult,
                BindingProjectionKind::TargetDeclaredValueType
                | BindingProjectionKind::TargetTypeOrDeclaredValueType =>
                    ResolutionTypeSlotRole::ExpressionValue,
            }),
            "a projection's output slot carries the role its kind implies: {:?}",
            projection.kind()
        );
        assert!(
            projected_slots.insert(projection.output_slot()),
            "one typed frontier has one producer: {:?}",
            projection.output_slot()
        );
    }
    for transfer in typed.transfers() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            !projected_slots.contains(&transfer.rule().target_slot()),
            "one typed frontier has one producer: {:?}",
            transfer.rule().target_slot()
        );
    }
    // A transfer-owned type-identity observation is exactly one that a
    // type-identity transfer feeds and no binding projection touches. This was
    // the `resolution_type_identity_observations_validate` trigger.
    for frontier in typed.frontiers() {
        if cancellation.is_cancelled() {
            return false;
        }
        let Some((reference, _)) = frontier.type_identity_reference() else {
            continue;
        };
        assert!(
            reference_semantics.contains(&reference),
            "a type-identity observation names a reference site: {reference}"
        );
        assert!(
            type_identity_targets.contains(&frontier.slot())
                && !projected_slots.contains(&frontier.slot()),
            "invalid transfer-owned type identity observation: {:?}",
            frontier.slot()
        );
    }
    for route in typed.qualified_routes() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_shared_reference_lookup_identity(
            route.source_lookup(),
            lowered.identities(),
            keys,
            rows,
        );
        keys.semantic(route.reference());
        keys.semantic(route.qualifier_slot());
        keys.semantic(route.lookup());
        keys.semantic(route.projection_output_slot());
        keys.semantic(route.coarse_gap_reason());
    }
    for property in typed.declaration_visibilities() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.declaration_visibility_properties.push(row![
            keys.semantic(property.definition()),
            property.visibility().label(),
        ]);
    }
    for property in typed.member_scopes() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.member_scope_properties.push(row![
            keys.semantic(property.definition()),
            keys.node(property.scope_head()),
        ]);
    }
    for property in typed.member_owners() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.member_owner_properties.push(row![
            keys.semantic(property.definition()),
            keys.semantic(property.owner_definition()),
            keys.node(property.owner_scope_head()),
            property.kind().label(),
            property.access().label(),
            property.qualifier_compatibility().label(),
        ]);
    }
    true
}

/// One row per (blob, relation, shared identity) the blob's typed facts carry.
///
/// A typed read resolves a workspace-shared request through this family: the
/// mounts it opens are the blobs that hold a fact of that relation under that
/// identity, which is exactly the blobs whose interior index can answer it.
/// The pass therefore mirrors `TypedSelection`, the interior index the reads
/// consult, key for key: every entry that index would build under a shared
/// identity gets a row here, and nothing else does.
///
/// A fragment-local key needs no row. `semantic_coordinates`' direct branch
/// resolves it through the rebaser to the one mount that owns it, and every
/// typed row's own semantics -- slots, references, definitions, frontiers and
/// gap reasons -- are fragment-local by construction, which
/// `assert_typed_identity_spaces` holds. Only a name recipe and an intrinsic
/// type identity are shared, so most relations carry rows only where a read
/// can actually be asked a shared question.
///
/// Two relations carry no rows at all and say so here rather than by omission:
/// a Rust reference context and a Rust declaration authority are keyed on the
/// reference or definition semantic of their own blob, which is fragment-local,
/// so the shared branch of those two reads is empty by construction.
fn prepare_typed_fact_lookups(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let identities = lowered.identities();
    let typed = lowered.typed();
    for frontier in typed.frontiers() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::TypedFrontierSlot,
            frontier.slot(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::TypeFrontierCompletionFrontier,
            frontier.slot(),
        );
        if let Some((reference, _)) = frontier.type_identity_reference() {
            push_typed_fact_lookup(
                rows,
                identities,
                TypedFactRelation::TypeIdentityObservationReference,
                reference,
            );
        }
    }
    for seed in typed.intrinsic_seeds() {
        if cancellation.is_cancelled() {
            return false;
        }
        let state = seed.frontier();
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::IntrinsicSeedSlot,
            state.slot(),
        );
        // The type identity a seeded value carries is the one shared key of
        // the typed layer that is not a name recipe. The read keyed on it is
        // the reverse walk asking whether an owner it reached is intrinsic;
        // most owners are not, and for those this relation names no blob
        // where membership named every blob that spells the owner's name.
        for value in state.possible_values() {
            push_typed_fact_lookup(
                rows,
                identities,
                TypedFactRelation::IntrinsicSeedTypeIdentity,
                value.ty().identity(),
            );
        }
    }
    for projection in typed.projections() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::BindingProjectionReference,
            projection.reference(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::BindingProjectionOutputSlot,
            projection.output_slot(),
        );
    }
    for route in typed.qualified_routes() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::QualifiedRouteReference,
            route.reference(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::QualifiedRouteQualifierSlot,
            route.qualifier_slot(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::QualifiedRouteGapReason,
            route.coarse_gap_reason(),
        );
        // The interior indexes a route under its completion lookup and, when
        // they differ, under its source lookup, and the slot-keyed read takes
        // the same index with the qualifier slot fixed. One relation, three
        // reads, because it is one question.
        for lookup in [route.lookup(), route.source_lookup()] {
            let identity = identities
                .semantic_identity(lookup)
                .expect("a qualified route names a catalog lookup semantic");
            // Every route lookup is a name recipe, so every blob that holds a
            // route holds at least one row here. That is what lets the route
            // inventory, which has no lookup to key on, read this relation
            // with no identity predicate and still be exact.
            assert_eq!(
                identity.space(),
                ResolutionSemanticIdentitySpace::Shared,
                "a qualified route lookup is a shared name recipe: {lookup:?}"
            );
            push_typed_fact_lookup(
                rows,
                identities,
                TypedFactRelation::QualifiedRouteLookup,
                lookup,
            );
        }
    }
    for transfer in typed.transfers() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::TypeTransferSourceSlot,
            transfer.source_slot(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::TypeTransferTargetSlot,
            transfer.rule().target_slot(),
        );
    }
    for property in typed.declaration_types() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DeclarationTypeDefinition,
            property.definition(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DeclarationTypeSlot,
            property.slot(),
        );
    }
    for property in typed.declaration_visibilities() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DeclarationVisibilityDefinition,
            property.definition(),
        );
    }
    for property in typed.member_scopes() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::MemberScopeDefinition,
            property.definition(),
        );
    }
    for property in typed.member_owners() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::MemberOwnerDefinition,
            property.definition(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::MemberOwnerOwnerDefinition,
            property.owner_definition(),
        );
    }
    for property in typed.deferred_member_owners() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DeferredMemberOwnerDefinition,
            property.definition(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DeferredMemberOwnerLookup,
            property.lookup(),
        );
    }
    for property in typed.construction_requirements() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::ConstructionRequirementDefinition,
            property.definition(),
        );
    }
    for property in typed.supertypes() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::SupertypeDefinition,
            property.definition(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::SupertypeReference,
            property.reference(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::SupertypeFrontier,
            property.frontier(),
        );
    }
    for gap in typed.property_gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DefinitionPropertyGapDefinition,
            gap.definition(),
        );
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::DefinitionPropertyGapReason,
            gap.reason_semantic(),
        );
    }
    for obligation in typed.call_obligations() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::CallApplicabilityCalleeReference,
            obligation.callee_reference(),
        );
    }
    for signature in typed.callable_signatures() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::CallableSignatureDefinition,
            signature.definition(),
        );
    }
    // The lexical gaps carry two typed keys the typed fragment does not: a
    // gap's own reason, which the provenance read is keyed on, and the type
    // frontier a gap lands on, which folds into the frontier completion index
    // and can name a synthetic frontier no typed row declares.
    for gap in lowered.lexical().gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        push_typed_fact_lookup(
            rows,
            identities,
            TypedFactRelation::GapReasonProvenanceReason,
            gap.reason_semantic(),
        );
        if gap.origin()
            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
        {
            push_typed_fact_lookup(
                rows,
                identities,
                TypedFactRelation::CallApplicabilityGapReason,
                gap.reason_semantic(),
            );
        }
        if let LoweringCoverageFrontier::Type { frontier } = gap.frontier() {
            push_typed_fact_lookup(
                rows,
                identities,
                TypedFactRelation::TypeFrontierCompletionFrontier,
                frontier,
            );
        }
    }
    true
}

/// Record one membership row, or nothing when the key is fragment-local.
///
/// A fragment-local key resolves to its own mount through the rebaser without
/// consulting any relation, so a row for it would be dead weight.
fn push_typed_fact_lookup(
    rows: &mut PreparedResolutionBundleRows,
    identities: &ResolutionIdentityCatalog,
    relation: TypedFactRelation,
    semantic: SemanticId,
) {
    let identity = identities.semantic_identity(semantic).unwrap_or_else(|| {
        panic!(
            "typed fact key {semantic} for {} is outside the identity catalog",
            relation.label()
        )
    });
    let Some(name) = identity.shared_name() else {
        return;
    };
    rows.typed_fact_lookups
        .push(row![relation.code(), identities.shared_name_digest(name)]);
}

/// `resolution_fragment_interiors_validate_typed_semantic_ownership` proved
/// that every typed row names a lexical owner of the same blob. The node
/// relation it joined is interior detail now; the lowered fragment carries the
/// same ownership, so the check runs where the interior is built.
fn assert_typed_semantic_ownership(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    references: &HashSet<SemanticId>,
    definitions: &HashSet<SemanticId>,
) -> bool {
    let typed = lowered.typed();
    let scope_nodes = lowered
        .lexical()
        .nodes()
        .iter()
        .filter(|(_, kind)| matches!(kind, BindingNodeKind::Scope))
        .map(|(node, _)| *node)
        .collect::<HashSet<_>>();
    let mut referencing = typed
        .projections()
        .iter()
        .map(LoweredBindingProjection::reference)
        .chain(
            typed
                .qualified_routes()
                .iter()
                .map(LoweredQualifiedSeededRoute::reference),
        )
        .chain(
            typed
                .supertypes()
                .iter()
                .map(LoweredSupertypeProperty::reference),
        )
        .chain(
            typed
                .call_obligations()
                .iter()
                .map(LoweredCallApplicabilityObligation::callee_reference),
        );
    assert!(
        referencing.all(|semantic| references.contains(&semantic)),
        "a typed row's reference must be a reference site of the same blob"
    );
    let mut defining = typed
        .declaration_types()
        .iter()
        .map(LoweredDeclarationTypeProperty::definition)
        .chain(
            typed
                .declaration_visibilities()
                .iter()
                .map(LoweredDeclarationVisibilityProperty::definition),
        )
        .chain(
            typed
                .member_scopes()
                .iter()
                .map(LoweredMemberScopeProperty::definition),
        )
        .chain(
            typed
                .member_owners()
                .iter()
                .flat_map(|owner| [owner.definition(), owner.owner_definition()]),
        )
        .chain(
            typed
                .supertypes()
                .iter()
                .map(LoweredSupertypeProperty::definition),
        )
        .chain(
            typed
                .property_gaps()
                .iter()
                .map(LoweredDefinitionPropertyGap::definition),
        )
        .chain(
            typed
                .callable_signatures()
                .iter()
                .map(LoweredCallableSignatureProperty::definition),
        );
    assert!(
        defining.all(|semantic| definitions.contains(&semantic)),
        "a typed row's definition must be a definition site of the same blob"
    );
    assert!(
        typed
            .member_scopes()
            .iter()
            .all(|scope| scope_nodes.contains(&scope.scope_head())),
        "a member scope head must be a scope node of the same blob"
    );
    assert!(
        typed
            .member_owners()
            .iter()
            .all(|owner| scope_nodes.contains(&owner.owner_scope_head())),
        "a member owner's scope head must be a scope node of the same blob"
    );
    true
}

/// `resolution_fragment_interiors_validate_typed_identity_spaces` proved that
/// a typed row's own semantics are fragment-local and the names it looks up
/// are shared, and that every lookup carries a recipe. The term catalog it
/// read is interior detail; the identity catalog holds the same spaces.
fn assert_typed_identity_spaces(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) -> bool {
    let identities = lowered.identities();
    let typed = lowered.typed();
    let space = |semantic: SemanticId| {
        identities
            .semantic_identity(semantic)
            .map(|identity| identity.space())
    };
    let local = typed
        .frontiers()
        .iter()
        .map(LoweredTypedFrontier::slot)
        .chain(
            typed
                .transfers()
                .iter()
                .map(|transfer| transfer.rule().semantic()),
        )
        .chain(
            typed
                .projections()
                .iter()
                .map(LoweredBindingProjection::reference),
        )
        .chain(
            typed
                .qualified_routes()
                .iter()
                .flat_map(|route| [route.reference(), route.coarse_gap_reason()]),
        )
        .chain(
            typed
                .member_owners()
                .iter()
                .flat_map(|owner| [owner.definition(), owner.owner_definition()]),
        );
    for semantic in local {
        if cancellation.is_cancelled() {
            return false;
        }
        assert_eq!(
            space(semantic),
            Some(ResolutionSemanticIdentitySpace::FragmentLocal),
            "a typed row's own semantic {semantic} must be fragment-local"
        );
    }
    let shared = typed
        .qualified_routes()
        .iter()
        .flat_map(|route| [route.lookup(), route.source_lookup()])
        .chain(
            typed
                .deferred_member_owners()
                .iter()
                .map(LoweredDeferredMemberOwner::lookup),
        );
    for semantic in shared {
        if cancellation.is_cancelled() {
            return false;
        }
        assert_eq!(
            space(semantic),
            Some(ResolutionSemanticIdentitySpace::Shared),
            "a typed row's lookup {semantic} must be shared"
        );
        assert!(
            identities.lookup_recipe(semantic).is_some(),
            "a typed row's lookup {semantic} must carry a recipe"
        );
    }
    true
}

/// Source lowering proves visibility coverage for source declarations. This
/// normalized-row check keeps every declared member covered while allowing a
/// synthetic anonymous type to own a member scope without source visibility.
fn assert_declaration_visibility_coverage(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
) -> bool {
    if lowered.lexical().language() != Language::Java {
        return true;
    }
    let typed = lowered.typed();
    let members = typed
        .member_owners()
        .iter()
        .map(LoweredMemberOwnerProperty::definition)
        .collect::<HashSet<_>>();
    let types = typed
        .member_scopes()
        .iter()
        .map(LoweredMemberScopeProperty::definition)
        .collect::<HashSet<_>>();
    let known = types.union(&members).copied().collect::<HashSet<_>>();
    let published = typed
        .declaration_visibilities()
        .iter()
        .map(LoweredDeclarationVisibilityProperty::definition)
        .collect::<HashSet<_>>();
    assert!(
        members.is_subset(&published),
        "each Java member declaration publishes visibility: members={members:?}, published={published:?}"
    );
    assert!(
        published.is_subset(&known),
        "Java visibility rows name known type or member definitions: published={published:?}, known={known:?}"
    );
    let unsupported = typed
        .property_gaps()
        .iter()
        .filter(|gap| gap.kind() == ResolutionGapKind::UnsupportedVisibility)
        .map(LoweredDefinitionPropertyGap::definition)
        .collect::<HashSet<_>>();
    for property in typed.declaration_visibilities() {
        let requires_gap = !matches!(
            property.visibility(),
            DeclaredVisibility::Public | DeclaredVisibility::Unknown
        );
        assert_eq!(
            requires_gap,
            unsupported.contains(&property.definition()),
            "a restricted Java access level is exactly one with an unsupported-visibility gap: {:?}",
            property.definition()
        );
    }
    true
}

fn serialized_completion(
    completion: &ResolutionCompletion,
    keys: &ResolutionLocalKeys,
    cancellation: &CancellationToken,
) -> Option<(&'static str, Vec<Box<[PreparedResolutionValue]>>)> {
    match completion {
        ResolutionCompletion::Complete => Some((completion.kind().label(), Vec::new())),
        ResolutionCompletion::Incomplete(reasons) => {
            let mut canonical = BTreeSet::new();
            for reason in reasons.iter() {
                if cancellation.is_cancelled() {
                    return None;
                }
                assert!(
                    canonical.insert(serialized_completion_reason(*reason, keys)),
                    "lowered completion reasons must be unique after storage-local rebasing"
                );
            }
            let serialized = canonical.into_iter().collect::<Vec<_>>();
            assert_eq!(
                serialized.len(),
                reasons.len(),
                "lowered completion reasons must be unique after storage-local rebasing"
            );
            Some((completion.kind().label(), serialized))
        }
    }
}

fn serialized_completion_reason(
    reason: ResolutionIncompleteReason,
    keys: &ResolutionLocalKeys,
) -> Box<[PreparedResolutionValue]> {
    match reason {
        ResolutionIncompleteReason::Cancelled => {
            panic!("operation-local cancellation is not persistable completion evidence")
        }
        ResolutionIncompleteReason::CyclicPrefixDependency(_) => {
            panic!("an unpublished cyclic prefix dependency is not persistable evidence")
        }
        ResolutionIncompleteReason::ReceiverBudgetExhausted(_) => {
            panic!("an operation-local receiver budget stop is not persistable evidence")
        }
        ResolutionIncompleteReason::TimeBudgetExceeded(_) => {
            panic!("an operation-local time budget stop is not persistable evidence")
        }
        ResolutionIncompleteReason::UnmountedFile { fragment } => panic!(
            "an operation-local unmounted-file route is not persistable evidence: {fragment:?}"
        ),
        ResolutionIncompleteReason::CyclicExpansion(path) => vec![
            ResolutionCompletionReasonKind::CyclicExpansion
                .label()
                .into(),
            keys.path(path).into(),
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::InconsistentPrecedence(semantic) => vec![
            ResolutionCompletionReasonKind::InconsistentPrecedence
                .label()
                .into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::OpenBoundary { semantic, status } => vec![
            ResolutionCompletionReasonKind::OpenBoundary.label().into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            status.label().into(),
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::UnsupportedSemantic(semantic) => vec![
            ResolutionCompletionReasonKind::UnsupportedSemantic
                .label()
                .into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
    }
}

fn dense_key(index: usize) -> i64 {
    i64::try_from(index).expect("resolution family length fits SQLite INTEGER")
}

fn usize_i64(value: usize) -> i64 {
    i64::try_from(value).expect("resolution row count fits SQLite INTEGER")
}

const fn qualified_namespace_label(namespace: ResolutionNamespace) -> &'static str {
    if matches!(namespace, ResolutionNamespace::TypeOrValue) {
        panic!("a persisted qualified route must have an exact namespace")
    }
    namespace.label()
}

const fn semantic_role_label(role: LoweredSemanticRole) -> &'static str {
    match role {
        LoweredSemanticRole::Reference => "reference",
        LoweredSemanticRole::Definition => "definition",
    }
}

const fn definition_gap_kind_label(kind: ResolutionGapKind) -> &'static str {
    match kind {
        ResolutionGapKind::ImplicitConstructor
        | ResolutionGapKind::UnsupportedHierarchyTraversal
        | ResolutionGapKind::UnsupportedVisibility => kind.label(),
        _ => panic!("definition property gap kind is not persistable"),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionGapFact, ResolutionScopeFact, ResolutionScopeId,
        ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
        ResolutionSiteKind,
    };

    use crate::analyzer::resolution::{BindingFragmentId, rich_java_resolution_facts_for_test};

    use super::*;

    fn gap_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: ResolutionScopeId::new(0),
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: 0,
                end_byte: 100,
            }],
            sites: vec![ResolutionSiteFact {
                id: ResolutionSiteId::new(0),
                scope: ResolutionScopeId::new(0),
                kind: ResolutionSiteKind::UnsupportedExpression,
                start_byte: 20,
                end_byte: 21,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        }
    }

    fn prepared(
        fragment_byte: u8,
        cancellation: &CancellationToken,
    ) -> ResolutionInteriorPreparation {
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test([fragment_byte]),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &gap_facts(),
        );
        prepare_resolution_bundle_with_unit_keys(&lowered, None, cancellation)
    }

    #[test]
    fn node_payload_round_trips_all_kinds_and_catalog_only_authority() {
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"node-payload-roundtrip"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &rich_java_resolution_facts_for_test(),
        );
        let catalog = lowered.identities();
        let keys = ResolutionLocalKeys::new(&lowered, &CancellationToken::default()).unwrap();
        let local = catalog
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_none())
            .unwrap()
            .0;
        let shared = catalog
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_some())
            .unwrap()
            .0;
        let target = catalog.nodes()[0].0;
        let mut kinds = vec![
            None,
            Some(BindingNodeKind::Root),
            Some(BindingNodeKind::Scope),
            Some(BindingNodeKind::DropScopes),
            Some(BindingNodeKind::JumpToScope(target)),
            Some(BindingNodeKind::JumpToScope(BindingNodeId::universal_root())),
        ];
        for semantic in [local, shared] {
            kinds.extend(
                [
                    BindingNodeKind::PushSymbol(semantic),
                    BindingNodeKind::PopSymbol(semantic),
                    BindingNodeKind::PushScopedSymbol(semantic),
                    BindingNodeKind::PopScopedSymbol(semantic),
                    BindingNodeKind::Reference(semantic),
                    BindingNodeKind::Definition(semantic),
                ]
                .map(Some),
            );
        }
        for original in kinds {
            let payload = prepare_node_payload(original, &keys, catalog);
            let semantic = match (payload.semantic_local_key, payload.semantic_shared_identity) {
                (Some(key), None) => Some(catalog.semantics()[key as usize].0),
                (None, Some(digest)) => Some(
                    catalog
                        .semantics()
                        .iter()
                        .find(|(_, identity)| {
                            identity
                                .shared_name()
                                .is_some_and(|name| catalog.shared_name_digest(name) == digest)
                        })
                        .unwrap()
                        .0,
                ),
                (None, None) => None,
                _ => panic!("exclusive semantic coordinate"),
            };
            let target = match (&payload.target.local_key, &payload.target.boundary_key) {
                (PreparedResolutionValue::Integer(key), PreparedResolutionValue::Null) => {
                    Some(catalog.nodes()[*key as usize].0)
                }
                (PreparedResolutionValue::Null, PreparedResolutionValue::Integer(0)) => {
                    Some(BindingNodeId::universal_root())
                }
                (PreparedResolutionValue::Null, PreparedResolutionValue::Null) => None,
                _ => panic!("exclusive local or universal-root target"),
            };
            let decoded = payload.kind.map(|kind| match kind {
                0 => BindingNodeKind::Root,
                1 => BindingNodeKind::Scope,
                2 => BindingNodeKind::PushSymbol(semantic.unwrap()),
                3 => BindingNodeKind::PopSymbol(semantic.unwrap()),
                4 => BindingNodeKind::PushScopedSymbol(semantic.unwrap()),
                5 => BindingNodeKind::PopScopedSymbol(semantic.unwrap()),
                6 => BindingNodeKind::DropScopes,
                7 => BindingNodeKind::JumpToScope(target.unwrap()),
                8 => BindingNodeKind::Reference(semantic.unwrap()),
                9 => BindingNodeKind::Definition(semantic.unwrap()),
                _ => panic!("known node kind"),
            });
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn source_aware_preparation_has_known_empty_non_rust_authority_and_requires_rust_source() {
        let cancellation = CancellationToken::new();
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"empty-authority"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &gap_facts(),
        );
        let ResolutionInteriorPreparation::Prepared(bundle) =
            prepare_resolution_bundle_with_source_facts(
                &lowered,
                &HashMap::default(),
                None,
                &cancellation,
            )
            .unwrap()
        else {
            panic!("live preparation");
        };
        let columns = super::super::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;
        let counts = bundle.family_counts();
        for name in [
            "expected_rust_reference_context_count",
            "expected_rust_declaration_authority_count",
        ] {
            assert_eq!(
                counts[columns.iter().position(|column| *column == name).unwrap()],
                0
            );
        }
        let rust = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"missing-source"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &gap_facts(),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                prepare_resolution_bundle_with_source_facts(
                    &rust,
                    &HashMap::default(),
                    None,
                    &cancellation,
                )
            }))
            .is_err(),
            "Rust publication requires canonical source input even when no reference authority rows result"
        );
    }

    #[test]
    fn preparation_rebases_mounted_ids_to_equal_storage_local_bundles() {
        let ResolutionInteriorPreparation::Prepared(first) =
            prepared(1, &CancellationToken::default())
        else {
            panic!("uncancelled preparation must finish")
        };
        let ResolutionInteriorPreparation::Prepared(second) =
            prepared(2, &CancellationToken::default())
        else {
            panic!("uncancelled preparation must finish")
        };

        assert_eq!(first.semantic_language(), Language::Rust);
        assert_eq!(first, second);
        // The fixture's one unsupported expression is interior detail from
        // end to end, so what the rebasing must reproduce exactly is the
        // bundle itself, digest and accounting included.
        assert_eq!(first.interior_digest(), second.interior_digest());
    }

    #[test]
    fn java_root_shadow_preparation_is_storage_local_across_a_to_b_to_a() {
        let facts = rich_java_resolution_facts_for_test();
        let cancellation = CancellationToken::default();
        let bundles = [1_u8, 2, 1].map(|fragment_byte| {
            let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                BindingFragmentId::for_test([fragment_byte]),
                crate::analyzer::resolution::test_shared_names(),
                Language::Java,
                &facts,
            );
            let ResolutionInteriorPreparation::Prepared(bundle) =
                prepare_resolution_bundle_with_unit_keys(&lowered, None, &cancellation)
            else {
                panic!("uncancelled Java root-shadow preparation must finish")
            };
            *bundle
        });

        assert_eq!(bundles[0], bundles[1]);
        assert_eq!(bundles[0], bundles[2]);
        assert_eq!(
            bundles[0].producer_epoch(),
            crate::analyzer::store::resolution::resolution_bundle_epoch(Language::Java)
        );
        let endpoint_header_family = super::super::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .position(|column| *column == "expected_path_endpoint_header_count")
            .expect("path endpoint header manifest family");
        assert!(bundles[0].family_counts()[endpoint_header_family] > 1);
    }

    #[test]
    fn preparation_returns_explicit_cancellation_before_publication() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            prepared(1, &cancellation),
            ResolutionInteriorPreparation::Cancelled
        ));
    }

    #[test]
    fn local_keys_are_exact_indexes_into_descriptor_sorted_catalogs() {
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"digest-3"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &rich_java_resolution_facts_for_test(),
        );
        let keys = ResolutionLocalKeys::new(&lowered, &CancellationToken::default())
            .expect("uncancelled key construction");
        let catalog = lowered.identities();
        assert!(!catalog.semantics().is_empty());
        assert!(!catalog.nodes().is_empty());
        assert!(!catalog.paths().is_empty());
        assert!(!catalog.stack_variables().is_empty());

        for (index, &(mounted, expected)) in catalog.semantics().iter().enumerate() {
            let key = keys.semantic(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.semantics(), mounted, key, "semantic test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.nodes().iter().enumerate() {
            let key = keys.node(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.nodes(), mounted, key, "node test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.paths().iter().enumerate() {
            let key = keys.path(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.paths(), mounted, key, "path test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.stack_variables().iter().enumerate() {
            let key = keys.variable(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(
                    catalog.stack_variables(),
                    mounted,
                    key,
                    "stack-variable test catalog",
                ),
                expected
            );
        }

        assert_eq!(
            keys.node_coordinate(BindingNodeId::universal_root()),
            PreparedNodeCoordinate {
                local_key: PreparedResolutionValue::Null,
                boundary_key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY.into(),
            }
        );
        let local_node = lowered.lexical().nodes()[0].0;
        assert_eq!(
            keys.node_coordinate(local_node),
            PreparedNodeCoordinate {
                local_key: keys.node(local_node).into(),
                boundary_key: PreparedResolutionValue::Null,
            }
        );
        let unknown = BindingNodeId::for_test(b"unknown-non-root-node");
        assert!(
            catch_unwind(AssertUnwindSafe(|| keys.node_coordinate(unknown))).is_err(),
            "only the exact universal root may bypass the local identity catalog"
        );
    }
}
