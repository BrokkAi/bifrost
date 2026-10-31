//! Canonical identity, physical grouping, and identity routes (#1475, M3).
//!
//! A declaration's *canonical identity* is its structured semantic identity —
//! language, namespace, ordered kind-tagged segments, generic arity — and its
//! *physical occurrences* are the concrete source locations that share it (a
//! C# partial type's parts, a C++ prototype/body pair). An *identity route*
//! is the typed record of how identity flows through indirection: each hop is
//! one alias, import, export, re-export, partial-part, peer, nested-owner, or
//! implementation relation, with the site that makes it real as provenance.
//!
//! Before this module every one of those relations was a private step inside
//! one consumer. Here they become per-file rows derived from producers that
//! already compute them — occurrence-row resolution for import/export/alias
//! sites, the type-alias capability for alias declarations, `FqName` parents
//! for nested owners, and three analyzer capabilities (partial parts, abstract
//! member implementations, declaration/definition peers) — plus one cycle-safe
//! bounded traversal over the rows, forward and inverse, so a round trip is
//! checkable.
//!
//! The load-bearing properties are the sibling layers': grammar and language
//! knowledge stays behind adapter hooks and analyzer capabilities; endpoints
//! compare structurally (`CodeUnit` equality, never rendered names); and a
//! traversal that stops early says why (`RouteTermination`), never silently.

use super::facts::FileFacts;

use super::kinds::NormalizedKind;

use super::occurrence_rows::OccurrenceRow;
use super::occurrence_rows::OccurrenceTarget;
use super::occurrence_rows::occurrences_for_file;

use super::occurrences::Namespace;
use super::occurrences::OccurrenceRole;

use super::routes::CanonicalIdentity;
use super::routes::CuratedExportSurface;
use super::routes::IdentityAxis;
use super::routes::RouteHopKind;
use super::routes::RouteTermination;

use super::spec::StructuralSpec;

use crate::analyzer::common::language_for_file;

use crate::analyzer::structural_spec_for;

use crate::analyzer::usages::get_definition::parse_tree_for_language;

use crate::analyzer::CodeUnit;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use crate::cancellation::CancellationToken;

use crate::hash::HashMap;

use std::collections::HashSet;

/// The structured semantic identity of `unit`: language from its source file,
/// namespace from its kind (a module binds a module name, a class-like unit a
/// type name, everything else a value name), segments decoded through the
/// process interner, and generic arity where the analyzer's signature
/// metadata records type parameters that every rendering agrees on.
///
/// `generic_arity` stays `None` when no metadata records type parameters or
/// when renderings disagree. A metadata row whose producer actually read the
/// declaration's type-parameter list contributes its length even when that
/// length is zero, so a nongeneric declaration in a recording language is
/// `Some(0)` and is never equal to an unrecorded one.
pub fn canonical_identity_of(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> CanonicalIdentity {
    canonical_member_identity(analyzer, unit).0
}

pub(crate) fn canonical_member_identity(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> (CanonicalIdentity, Option<[u8; 32]>) {
    let metadata = analyzer.signature_metadata(unit);
    let discriminator = metadata
        .iter()
        .find_map(|metadata| metadata.overload_discriminator().copied());
    let namespace = if unit.is_module() {
        Namespace::Module
    } else if unit.is_class() {
        Namespace::Type
    } else {
        Namespace::Value
    };
    let mut generic_arity: Option<u32> = None;
    for metadata in &metadata {
        let parameters = metadata.type_parameters();
        if parameters.is_empty() && !metadata.type_parameters_recorded() {
            continue;
        }
        let count = u32::try_from(parameters.len()).expect("type parameter count fits in u32");
        match generic_arity {
            None => generic_arity = Some(count),
            Some(existing) if existing == count => {}
            Some(_) => {
                generic_arity = None;
                break;
            }
        }
    }
    (
        CanonicalIdentity::from_fq(
            language_for_file(unit.source()),
            namespace,
            unit.fq(),
            crate::analyzer::fq_name::segment_interner(),
            generic_arity,
        ),
        discriminator,
    )
}

/// Stable member identity shared by candidate rows and member-family roots.
/// The declaration producer records canonical overload type tokens as a digest.
pub fn canonical_member_digest(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> String {
    let (identity, discriminator) = canonical_member_identity(analyzer, unit);
    canonical_member_digest_from_identity(&identity, discriminator.as_ref())
}

pub(crate) fn canonical_member_digest_from_identity(
    identity: &CanonicalIdentity,
    discriminator: Option<&[u8; 32]>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.canonical_member_id.v1");
    hasher.update(serde_json::to_vec(identity).expect("canonical identity serializes"));
    if let Some(discriminator) = discriminator {
        hasher.update(b"overload-discriminator");
        hasher.update(discriminator);
    }
    format!("{:x}", hasher.finalize())
}

/// One concrete source location of a canonical declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalOccurrence {
    pub file: ProjectFile,
    pub range: Range,
}

/// Every physical occurrence of `unit`: its own indexed ranges (a C++
/// prototype/body pair keeps both, per the #955 navigation work), plus — when
/// the language's adapter claims the partial-part relation — the ranges of
/// every partial part sharing its identity.
pub fn physical_occurrences(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<PhysicalOccurrence> {
    let mut occurrences = Vec::new();
    let push_unit = |target: &CodeUnit, occurrences: &mut Vec<PhysicalOccurrence>| {
        for range in analyzer.ranges_of(target) {
            let occurrence = PhysicalOccurrence {
                file: target.source().clone(),
                range,
            };
            if !occurrences.contains(&occurrence) {
                occurrences.push(occurrence);
            }
        }
    };
    push_unit(unit, &mut occurrences);
    let claims_partial_parts =
        structural_spec_for(language_for_file(unit.source())).is_some_and(|spec| {
            spec.identity_route_support()
                .supports_relation(RouteHopKind::PartialPart)
        });
    if claims_partial_parts && let Some(parts) = analyzer.partial_declaration_parts(unit) {
        for part in &parts {
            push_unit(part, &mut occurrences);
        }
    }
    occurrences
}

/// One declaration head paired with the definition body that completes it: a
/// C++ prototype and the out-of-line function body it declares (issue #1650).
///
/// `body_range` is the body occurrence's own range, never the body
/// declaration's merged range list, so a row built from this pair points at
/// the occurrence that makes the relation real. `head` and `body` are always
/// distinct declarations: two occurrences of one declaration are one identity
/// with two physical ranges, which is the physical-grouping answer rather than
/// an indirection hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationDefinitionPeer {
    /// The declaration whose occurrence in the queried file is a head.
    pub head: CodeUnit,
    /// The declaration that carries the definition body, here or in another
    /// file.
    pub body: CodeUnit,
    /// The body occurrence's own range, inside `body.source()`.
    pub body_range: Range,
}

/// One file's declaration/definition peers, and whether the adapter could read
/// every occurrence it needed to pair them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclarationDefinitionPeers {
    pub peers: Vec<DeclarationDefinitionPeer>,
    /// At least one occurrence of a declaration this file anchors could not be
    /// read as a head or a body, so `peers` can be short of the whole truth.
    /// The file's completeness says so, rather than letting a missing row read
    /// as an absence the adapter never established.
    pub unclassified_occurrences: bool,
}

/// One end of a route relation: a declaration, or a binder/export site that
/// is not itself a declaration (an import's local name, an export specifier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteEndpoint {
    Declaration(CodeUnit),
    Site {
        file: ProjectFile,
        range: Range,
        /// The decoded spelling at the site, carried for rendering; never an
        /// identity.
        name: String,
    },
}

impl RouteEndpoint {
    fn key(&self) -> EndpointKey {
        match self {
            RouteEndpoint::Declaration(unit) => EndpointKey::Declaration(unit.clone()),
            RouteEndpoint::Site { file, range, .. } => EndpointKey::Site(file.clone(), *range),
        }
    }

    /// The file whose relation rows can carry edges out of this endpoint.
    fn file(&self) -> &ProjectFile {
        match self {
            RouteEndpoint::Declaration(unit) => unit.source(),
            RouteEndpoint::Site { file, .. } => file,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum EndpointKey {
    Declaration(CodeUnit),
    Site(ProjectFile, Range),
}

/// The site that makes a relation real: the import binder token, the export
/// specifier, the partial part's own location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProvenance {
    pub file: ProjectFile,
    /// `None` when the evidence is a whole file rather than a span (a partial
    /// part in another file whose range the analyzer does not index).
    pub range: Option<Range>,
}

/// One typed indirection relation: identity flows from `from` to `to` through
/// a `kind` hop whose evidence is `provenance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRelationRow {
    pub kind: RouteHopKind,
    pub from: RouteEndpoint,
    pub to: RouteEndpoint,
    pub provenance: RouteProvenance,
}

/// Why a file's relation rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRelationIncompleteReason {
    /// The adapter does not supply edges for this relation, so absence of its
    /// rows says nothing about the file.
    RelationUnsupported(RouteHopKind),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file.
    FactsUnavailable,
    /// The occurrence rows the import/alias relations are derived from are
    /// themselves incomplete for the roles they need.
    OccurrenceRowsIncomplete,
    /// The adapter could not say which indirection relation at least one
    /// import site participates in, so the site-anchored relations are less
    /// than the whole truth. A Python module whose `__all__` the source
    /// computes is the case this exists for: membership decides whether an
    /// import re-exports, and an unreadable `__all__` settles it neither way.
    IndirectionUnclassified,
    /// An occurrence the declaration/definition peer producer had to read as a
    /// head or a body could not be read as either, so a peer of this file can
    /// be missing from the rows (issue #1650).
    PeerOccurrenceUnclassified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRelationCompleteness {
    Complete,
    Incomplete {
        unsupported_relations: Vec<RouteHopKind>,
        reasons: Vec<RouteRelationIncompleteReason>,
    },
}

impl RouteRelationCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows of `relation` can be trusted to be the complete set for
    /// the file.
    pub fn covers(&self, relation: RouteHopKind) -> bool {
        match self {
            Self::Complete => true,
            Self::Incomplete {
                unsupported_relations,
                reasons,
            } => {
                !unsupported_relations.contains(&relation)
                    && !reasons.iter().any(|reason| match reason {
                        RouteRelationIncompleteReason::RelationUnsupported(unsupported) => {
                            *unsupported == relation
                        }
                        // Only the site-anchored relations are classified per
                        // import token, so an unclassified site says nothing
                        // about the declaration-anchored ones.
                        RouteRelationIncompleteReason::IndirectionUnclassified => matches!(
                            relation,
                            RouteHopKind::Import | RouteHopKind::Export | RouteHopKind::ReExport
                        ),
                        // An occurrence the peer producer could not read leaves
                        // only the peer relation short.
                        RouteRelationIncompleteReason::PeerOccurrenceUnclassified => {
                            relation == RouteHopKind::DeclarationDefinitionPeer
                        }
                        RouteRelationIncompleteReason::NoStructuralAdapter
                        | RouteRelationIncompleteReason::FactsUnavailable
                        | RouteRelationIncompleteReason::OccurrenceRowsIncomplete => true,
                    })
            }
        }
    }
}

/// Every route relation row of one file.
#[derive(Debug, Clone)]
pub struct RouteRelationsFileResult {
    pub rows: Vec<RouteRelationRow>,
    pub completeness: RouteRelationCompleteness,
}

/// The derivation was cancelled before the rows were complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutesCancelled;

/// Derive every route relation row of `file` from producers the analyzer
/// already runs: occurrence-row resolution for import/export/alias sites, the
/// type-alias capability, `FqName` parents for nested owners, and the partial
/// part and implementation capabilities.
pub fn route_relations_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
) -> Result<RouteRelationsFileResult, RoutesCancelled> {
    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return Ok(unavailable(
            RouteRelationIncompleteReason::NoStructuralAdapter,
        ));
    };
    let support = spec.identity_route_support();
    let unsupported_relations: Vec<RouteHopKind> = super::routes::ALL_ROUTE_HOP_KINDS
        .iter()
        .copied()
        .filter(|relation| !support.supports_relation(*relation))
        .collect();
    let mut reasons: Vec<RouteRelationIncompleteReason> = unsupported_relations
        .iter()
        .copied()
        .map(RouteRelationIncompleteReason::RelationUnsupported)
        .collect();

    let mut rows = Vec::new();

    // Site-anchored relations (import, export, re-export, import alias) come
    // from occurrence rows, whose reference resolution is the producer that
    // knows each site's target.
    let needs_occurrences = [
        RouteHopKind::Import,
        RouteHopKind::Export,
        RouteHopKind::ReExport,
        RouteHopKind::Alias,
    ]
    .iter()
    .any(|relation| support.supports_relation(*relation));
    if needs_occurrences {
        let occurrences =
            occurrences_for_file(analyzer, file, cancellation).map_err(|_| RoutesCancelled)?;
        if !occurrences.completeness.is_complete() {
            let needed = [OccurrenceRole::ImportTarget, OccurrenceRole::ImportAlias];
            if needed
                .iter()
                .any(|&role| !occurrences.completeness.covers(role))
            {
                super::note_once(
                    &mut reasons,
                    RouteRelationIncompleteReason::OccurrenceRowsIncomplete,
                );
            }
        }
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(file));
        match facts {
            Some(facts) => {
                if let Some(reason) = site_relation_rows(
                    spec,
                    file,
                    &facts,
                    language,
                    &occurrences.rows,
                    support,
                    &mut rows,
                ) {
                    super::note_once(&mut reasons, reason);
                }
            }
            None => super::note_once(
                &mut reasons,
                RouteRelationIncompleteReason::FactsUnavailable,
            ),
        }
        // Alias declarations (type aliases) also read the occurrence rows.
        if support.supports_relation(RouteHopKind::Alias) {
            type_alias_rows(analyzer, file, &occurrences.rows, &mut rows);
        }
    }

    declaration_relation_rows(analyzer, file, support, &mut rows, &mut reasons);

    Ok(RouteRelationsFileResult {
        rows,
        completeness: if reasons.is_empty() {
            RouteRelationCompleteness::Complete
        } else {
            RouteRelationCompleteness::Incomplete {
                unsupported_relations,
                reasons,
            }
        },
    })
}

fn unavailable(reason: RouteRelationIncompleteReason) -> RouteRelationsFileResult {
    RouteRelationsFileResult {
        rows: Vec::new(),
        completeness: RouteRelationCompleteness::Incomplete {
            unsupported_relations: super::routes::ALL_ROUTE_HOP_KINDS.to_vec(),
            reasons: vec![reason],
        },
    }
}

/// Import/export/re-export rows from resolved import-target occurrences, and
/// alias rows from import-alias tokens paired with the target of the same
/// import declaration.
///
/// Returns the reason these rows are less than the whole truth, when the
/// adapter could not classify some site's indirection.
fn site_relation_rows(
    spec: &dyn StructuralSpec,
    file: &ProjectFile,
    facts: &FileFacts,
    language: crate::analyzer::Language,
    occurrence_rows: &[OccurrenceRow],
    support: &super::routes::IdentityRouteSupport,
    rows: &mut Vec<RouteRelationRow>,
) -> Option<RouteRelationIncompleteReason> {
    let tree = parse_tree_for_language(file, language, facts.source());
    // The file's curated export surface (Python's `__all__`) decides which of
    // its imports forward identity onward, so the adapter reads it once here
    // rather than per token.
    let surface = tree.as_ref().map_or(CuratedExportSurface::Absent, |tree| {
        spec.curated_export_surface(tree.root_node(), facts.source())
    });

    // The nearest enclosing Import-kind fact of each import-role token: the
    // pairing key between an alias binder and the target it respells.
    let import_fact_of = |node: u32| -> Option<u32> {
        let mut current = facts.node(node).parent;
        while let Some(index) = current {
            if facts.node(index).kind == NormalizedKind::Import {
                return Some(index);
            }
            current = facts.node(index).parent;
        }
        None
    };

    let mut target_rows: Vec<(&OccurrenceRow, Option<u32>, &[CodeUnit])> = Vec::new();
    for row in occurrence_rows {
        if row.role == OccurrenceRole::ImportTarget
            && let OccurrenceTarget::Resolved(units) = &row.target
        {
            target_rows.push((row, import_fact_of(row.node), units));
        }
    }

    // An unclassified site still carries the plain import its occurrence role
    // already states, but the file can no longer claim its site-anchored
    // relations are the whole truth.
    let mut unclassified = None;
    for &(row, _, units) in &target_rows {
        let classified = tree
            .as_ref()
            .and_then(|tree| {
                tree.root_node()
                    .descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
            })
            .and_then(|token| spec.indirection_relation(token, facts.source(), &surface));
        if classified.is_none() {
            unclassified = Some(RouteRelationIncompleteReason::IndirectionUnclassified);
        }
        let relation = classified.unwrap_or(RouteHopKind::Import);
        debug_assert!(
            support.supports_relation(relation),
            "adapter classified an indirection as {relation} without claiming that relation"
        );
        if !support.supports_relation(relation) {
            continue;
        }
        for unit in units {
            rows.push(RouteRelationRow {
                kind: relation,
                from: RouteEndpoint::Site {
                    file: file.clone(),
                    range: row.range,
                    name: row.effective_spelling().to_owned(),
                },
                to: RouteEndpoint::Declaration(unit.clone()),
                provenance: RouteProvenance {
                    file: file.clone(),
                    range: Some(row.range),
                },
            });
        }
    }

    if support.supports_relation(RouteHopKind::Alias) {
        for row in occurrence_rows {
            if row.role != OccurrenceRole::ImportAlias {
                continue;
            }
            let Some(import_fact) = import_fact_of(row.node) else {
                continue;
            };
            for &(target_row, target_fact, units) in &target_rows {
                if target_fact != Some(import_fact) {
                    continue;
                }
                // Several targets can share one import statement (a use
                // list); the alias respells the one whose declaration the
                // alias token is closest to — in every claimed grammar the
                // alias clause wraps its own target, so the nearest target
                // row by range distance is the wrapped one.
                if !alias_respells_target(facts, row, target_row) {
                    continue;
                }
                for unit in units {
                    rows.push(RouteRelationRow {
                        kind: RouteHopKind::Alias,
                        from: RouteEndpoint::Site {
                            file: file.clone(),
                            range: row.range,
                            name: row.effective_spelling().to_owned(),
                        },
                        to: RouteEndpoint::Declaration(unit.clone()),
                        provenance: RouteProvenance {
                            file: file.clone(),
                            range: Some(row.range),
                        },
                    });
                }
            }
        }
    }

    unclassified
}

/// Whether the alias token and the target token belong to the same alias
/// clause: the target is the nearest preceding import-target token inside the
/// same import fact, which is the structural shape of `x as y` in every
/// claimed grammar (the alias follows its own target, and no other target
/// token sits between them).
fn alias_respells_target(
    facts: &FileFacts,
    alias_row: &OccurrenceRow,
    target_row: &OccurrenceRow,
) -> bool {
    if target_row.range.start_byte >= alias_row.range.start_byte {
        return false;
    }
    // No other import-target token between the target and the alias.
    for node in target_row.node + 1..alias_row.node {
        if facts
            .occurrence_roles(node)
            .contains(&OccurrenceRole::ImportTarget)
        {
            return false;
        }
    }
    true
}

/// Alias rows for type-alias declarations: the alias unit points at what its
/// right-hand side resolves to, which the occurrence rows already computed.
fn type_alias_rows(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    occurrence_rows: &[OccurrenceRow],
    rows: &mut Vec<RouteRelationRow>,
) {
    let Some(provider) = analyzer.type_alias_provider() else {
        return;
    };
    for unit in analyzer.declarations(file) {
        if !provider.is_type_alias(&unit) {
            continue;
        }
        for row in occurrence_rows {
            if row.role != OccurrenceRole::TypeOperand || row.enclosing.as_ref() != Some(&unit) {
                continue;
            }
            let OccurrenceTarget::Resolved(units) = &row.target else {
                continue;
            };
            for target in units {
                if target == &unit {
                    continue;
                }
                rows.push(RouteRelationRow {
                    kind: RouteHopKind::Alias,
                    from: RouteEndpoint::Declaration(unit.clone()),
                    to: RouteEndpoint::Declaration(target.clone()),
                    provenance: RouteProvenance {
                        file: file.clone(),
                        range: Some(row.range),
                    },
                });
            }
        }
    }
}

/// Declaration-anchored relations: nested owners from `FqName` parents,
/// partial parts, abstract-member implementations, and declaration/definition
/// peers. Notes in `reasons` whichever occurrence the peer producer could not
/// read.
fn declaration_relation_rows(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    support: &super::routes::IdentityRouteSupport,
    rows: &mut Vec<RouteRelationRow>,
    reasons: &mut Vec<RouteRelationIncompleteReason>,
) {
    // The peer relation is asked once for the whole file, not once per
    // declaration: an adapter labels a head and a body by classifying the
    // file's occurrences in one pass, and a head's body routinely lives in
    // another file (issue #1650). Several bodies for one head are several
    // rows, each with its own provenance: two definitions of one external
    // callable are an ODR violation the rows state rather than hide.
    if support.supports_relation(RouteHopKind::DeclarationDefinitionPeer)
        && let Some(peers) = analyzer.declaration_definition_peers(file)
    {
        if peers.unclassified_occurrences {
            super::note_once(
                reasons,
                RouteRelationIncompleteReason::PeerOccurrenceUnclassified,
            );
        }
        for peer in peers.peers {
            debug_assert_ne!(
                peer.head, peer.body,
                "a peer relates two declarations; one declaration's own occurrences are its physical grouping"
            );
            let provenance = RouteProvenance {
                file: peer.body.source().clone(),
                range: Some(peer.body_range),
            };
            rows.push(RouteRelationRow {
                kind: RouteHopKind::DeclarationDefinitionPeer,
                from: RouteEndpoint::Declaration(peer.head),
                to: RouteEndpoint::Declaration(peer.body),
                provenance,
            });
        }
    }
    let declarations: Vec<CodeUnit> = analyzer.declarations(file).into_iter().collect();
    for unit in &declarations {
        if support.supports_relation(RouteHopKind::NestedOwner)
            && unit.fq().len() > unit.package_segment_count() + 1
            && let Some(parent_fq) = unit.fq().parent()
        {
            for owner in &declarations {
                if owner.fq() == &parent_fq && owner != unit {
                    rows.push(RouteRelationRow {
                        kind: RouteHopKind::NestedOwner,
                        from: RouteEndpoint::Declaration(unit.clone()),
                        to: RouteEndpoint::Declaration(owner.clone()),
                        provenance: RouteProvenance {
                            file: file.clone(),
                            range: analyzer.ranges_of(unit).into_iter().next(),
                        },
                    });
                }
            }
        }
        if support.supports_relation(RouteHopKind::PartialPart)
            && let Some(parts) = analyzer.partial_declaration_parts(unit)
        {
            for part in parts {
                let distinct_location = part.source() != unit.source()
                    || analyzer.ranges_of(&part) != analyzer.ranges_of(unit);
                if distinct_location {
                    rows.push(RouteRelationRow {
                        kind: RouteHopKind::PartialPart,
                        from: RouteEndpoint::Declaration(unit.clone()),
                        to: RouteEndpoint::Declaration(part.clone()),
                        provenance: RouteProvenance {
                            file: part.source().clone(),
                            range: analyzer.ranges_of(&part).into_iter().next(),
                        },
                    });
                }
            }
        }
        if support.supports_relation(RouteHopKind::Implementation)
            && let Some(implementations) = analyzer.abstract_member_implementations(unit)
        {
            for implementation in implementations {
                rows.push(RouteRelationRow {
                    kind: RouteHopKind::Implementation,
                    from: RouteEndpoint::Declaration(unit.clone()),
                    to: RouteEndpoint::Declaration(implementation.clone()),
                    provenance: RouteProvenance {
                        file: implementation.source().clone(),
                        range: analyzer.ranges_of(&implementation).into_iter().next(),
                    },
                });
            }
        }
    }
}

/// Traversal bounds. Both are deliberate constants rather than caller knobs
/// until a consumer needs otherwise.
pub const MAX_ROUTE_DEPTH: usize = 8;
pub const MAX_ROUTE_FAN_OUT: usize = 16;

/// One traversed route: ordered hops and why the traversal stopped there.
/// Any termination other than [`RouteTermination::Terminal`] means the last
/// hop is not the target — the route is evidence of a wall, not an answer.
#[derive(Debug, Clone)]
pub struct IdentityRoute {
    pub hops: Vec<RouteRelationRow>,
    pub termination: RouteTermination,
}

impl IdentityRoute {
    /// The declaration the route ends at, present exactly for terminal
    /// routes ending at a declaration endpoint.
    pub fn terminal_declaration(&self) -> Option<&CodeUnit> {
        if self.termination != RouteTermination::Terminal {
            return None;
        }
        match &self.hops.last()?.to {
            RouteEndpoint::Declaration(unit) => Some(unit),
            RouteEndpoint::Site { .. } => None,
        }
    }
}

/// Every identity route out of `start`, depth-first with an explicit stack,
/// bounded by [`MAX_ROUTE_DEPTH`] and [`MAX_ROUTE_FAN_OUT`], with cycles and
/// truncation as explicit terminations. Relation rows are derived per file on
/// demand and cached for the traversal.
pub fn identity_routes_from(
    analyzer: &dyn IAnalyzer,
    start: &RouteEndpoint,
    kinds: Option<&[RouteHopKind]>,
    cancellation: &CancellationToken,
) -> Result<Vec<IdentityRoute>, RoutesCancelled> {
    let mut rows_by_file: HashMap<ProjectFile, Vec<RouteRelationRow>> = HashMap::default();
    let mut routes = Vec::new();
    // Each frame: the endpoint to expand, the hops taken to reach it, and the
    // endpoint keys on the current path (for cycle detection).
    let mut stack: Vec<(RouteEndpoint, Vec<RouteRelationRow>, Vec<EndpointKey>)> =
        vec![(start.clone(), Vec::new(), vec![start.key()])];

    while let Some((endpoint, hops, path)) = stack.pop() {
        if cancellation.is_cancelled() {
            return Err(RoutesCancelled);
        }
        if hops.len() >= MAX_ROUTE_DEPTH {
            routes.push(IdentityRoute {
                hops,
                termination: RouteTermination::DepthTruncated,
            });
            continue;
        }
        let file = endpoint.file().clone();
        let file_rows = match rows_by_file.entry(file.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(route_relations_for_file(analyzer, &file, cancellation)?.rows)
            }
        };
        let outgoing: Vec<RouteRelationRow> = file_rows
            .iter()
            .filter(|row| row.from == endpoint)
            .filter(|row| kinds.is_none_or(|kinds| kinds.contains(&row.kind)))
            .cloned()
            .collect();
        if outgoing.is_empty() {
            if !hops.is_empty() {
                routes.push(IdentityRoute {
                    hops,
                    termination: RouteTermination::Terminal,
                });
            }
            continue;
        }
        let truncated = outgoing.len() > MAX_ROUTE_FAN_OUT;
        for row in outgoing.into_iter().take(MAX_ROUTE_FAN_OUT) {
            let mut next_hops = hops.clone();
            next_hops.push(row.clone());
            let next_key = row.to.key();
            if path.contains(&next_key) {
                routes.push(IdentityRoute {
                    hops: next_hops,
                    termination: RouteTermination::Cycle,
                });
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(next_key);
            stack.push((row.to.clone(), next_hops, next_path));
        }
        if truncated {
            routes.push(IdentityRoute {
                hops,
                termination: RouteTermination::FanOutTruncated,
            });
        }
    }
    Ok(routes)
}

/// The outcome of the forward/inverse round trip for one site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundTripOutcome {
    /// Every terminal declaration the forward traversal reaches also reaches
    /// the site back through inverse enumeration, and the identities agree.
    Holds { terminals: Vec<CodeUnit> },
    /// The forward traversal produced no terminal declaration, so there is
    /// nothing to round-trip; the routes say why (cycle, truncation, or no
    /// route at all).
    ForwardInconclusive,
    /// At least one forward terminal cannot be enumerated back to the site.
    InverseMisses { terminal: Box<CodeUnit> },
}

/// The hop kinds that forward one identity rather than projecting onto a
/// related one: a route through these ends at the same logical declaration
/// the start names. Projection hops (nested owner, partial part, peer,
/// implementation, generated peer) relate *different* identities and are
/// traversed only when a caller asks for them.
pub const IDENTITY_PRESERVING_HOPS: &[RouteHopKind] = &[
    RouteHopKind::Alias,
    RouteHopKind::Import,
    RouteHopKind::Export,
    RouteHopKind::ReExport,
];

/// Check the round trip for the site at `range` in `file`: resolve forward to
/// terminal declarations, then enumerate inverse edges over `scope` (the
/// files whose relation rows participate) and require the site to be
/// reachable from every terminal.
pub fn round_trip_from_site(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    name: &str,
    scope: &[ProjectFile],
    cancellation: &CancellationToken,
) -> Result<RoundTripOutcome, RoutesCancelled> {
    let start = RouteEndpoint::Site {
        file: file.clone(),
        range,
        name: name.to_owned(),
    };
    let routes = identity_routes_from(
        analyzer,
        &start,
        Some(IDENTITY_PRESERVING_HOPS),
        cancellation,
    )?;
    let mut terminals: Vec<CodeUnit> = Vec::new();
    for route in &routes {
        if let Some(unit) = route.terminal_declaration()
            && !terminals.contains(unit)
        {
            terminals.push(unit.clone());
        }
    }
    if terminals.is_empty() {
        return Ok(RoundTripOutcome::ForwardInconclusive);
    }

    // Inverse adjacency over the scope's rows: to-key -> from-keys.
    let mut inverse: HashMap<EndpointKey, Vec<EndpointKey>> = HashMap::default();
    for scope_file in scope {
        let result = route_relations_for_file(analyzer, scope_file, cancellation)?;
        for row in result.rows {
            inverse
                .entry(row.to.key())
                .or_default()
                .push(row.from.key());
        }
    }

    let start_key = start.key();
    for terminal in &terminals {
        let mut frontier = vec![EndpointKey::Declaration(terminal.clone())];
        let mut visited: HashSet<EndpointKey> = frontier.iter().cloned().collect();
        let mut reached = false;
        while let Some(key) = frontier.pop() {
            if key == start_key {
                reached = true;
                break;
            }
            for previous in inverse.get(&key).into_iter().flatten() {
                if visited.insert(previous.clone()) {
                    frontier.push(previous.clone());
                }
            }
        }
        if !reached {
            return Ok(RoundTripOutcome::InverseMisses {
                terminal: Box::new(terminal.clone()),
            });
        }
    }
    Ok(RoundTripOutcome::Holds { terminals })
}

/// Whether the file's language adapter supplies any route relation at all.
/// An adapter that supplies none cannot state the absence of a route, so a
/// consumer that finds no route there has a capability gap, not evidence.
pub fn file_supplies_route_relations(file: &ProjectFile) -> bool {
    structural_spec_for(language_for_file(file)).is_some_and(|spec| {
        super::routes::ALL_ROUTE_HOP_KINDS
            .iter()
            .any(|kind| spec.identity_route_support().supports_relation(*kind))
    })
}

/// The identity axes this module's physical grouping answers, mirrored by the
/// completeness accounting of the query layer built on top (Milestone 4).
pub const IDENTITY_ROUTE_PRODUCER_AXES: &[IdentityAxis] = &[
    IdentityAxis::CanonicalIdentity,
    IdentityAxis::PhysicalGrouping,
];

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::analyzer::{
        CodeUnitIndex, CodeUnitType, DeclarationInfo, FqName, Language, Project, SignatureMetadata,
        TestProject,
    };
    use std::collections::BTreeSet;

    pub(crate) struct MetadataAnalyzer {
        project: TestProject,
        pub metadata: Vec<SignatureMetadata>,
        pub units: Vec<CodeUnit>,
        pub imports: Vec<crate::analyzer::ImportInfo>,
    }
    impl MetadataAnalyzer {
        pub fn new(root: &std::path::Path) -> Self {
            Self {
                project: TestProject::new(root.to_path_buf(), Language::Python),
                metadata: vec![],
                units: vec![],
                imports: vec![],
            }
        }
    }
    impl CodeUnitIndex for MetadataAnalyzer {
        fn project(&self) -> &dyn Project {
            &self.project
        }
        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Python])
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.units.iter().cloned())
        }
        fn declarations(&self, _: &ProjectFile) -> BTreeSet<CodeUnit> {
            self.units.iter().cloned().collect()
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
            None
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<CodeUnit> {
            None
        }
        fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
        fn signature_metadata(&self, _: &CodeUnit) -> Vec<SignatureMetadata> {
            self.metadata.clone()
        }
    }
    impl crate::analyzer::ImportAnalysisProvider for MetadataAnalyzer {
        fn imported_code_units_of(
            &self,
            _: &ProjectFile,
        ) -> std::sync::Arc<crate::hash::HashSet<CodeUnit>> {
            unimplemented!()
        }
        fn referencing_files_of(&self, _: &ProjectFile) -> crate::hash::HashSet<ProjectFile> {
            unimplemented!()
        }
        fn import_info_of(
            &self,
            _: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
            _: &ProjectFile,
        ) -> Vec<crate::analyzer::ImportInfo> {
            self.imports.clone()
        }
    }
    impl IAnalyzer for MetadataAnalyzer {
        fn import_analysis_provider(&self) -> Option<&dyn crate::analyzer::ImportAnalysisProvider> {
            Some(self)
        }

        fn update(&self, _: &BTreeSet<ProjectFile>) -> Self {
            unimplemented!()
        }
        fn update_all(&self) -> Self {
            unimplemented!()
        }
        fn is_access_expression(&self, _: &ProjectFile, _: usize, _: usize) -> bool {
            unimplemented!()
        }
        fn find_nearest_declaration(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
            _: &str,
        ) -> Option<DeclarationInfo> {
            unimplemented!()
        }
    }

    #[test]
    fn canonical_arity_is_consensus_over_recorded_renderings() {
        let temp = tempfile::tempdir().unwrap();
        let mut analyzer = MetadataAnalyzer::new(temp.path());
        let unit = CodeUnit::new(
            ProjectFile::new(temp.path(), "example.py"),
            CodeUnitType::Class,
            "p",
            "C",
        );
        for arities in [
            vec![],
            vec![0],
            vec![1, 1, 1],
            vec![0, 1, 2],
            vec![2, 0, 1],
            vec![1, 2, 0],
            vec![2, 2, 0],
        ] {
            let unique = arities.iter().copied().collect::<BTreeSet<_>>();
            let expected = if unique.len() == 1 {
                unique.first().copied()
            } else {
                None
            };
            for reverse in [false, true] {
                analyzer.metadata = arities
                    .iter()
                    .map(|&arity| {
                        SignatureMetadata::new("rendering", vec![]).with_recorded_type_parameters(
                            (0..arity).map(|i| format!("T{i}")).collect(),
                        )
                    })
                    .collect();
                analyzer
                    .metadata
                    .push(SignatureMetadata::new("unrecorded", vec![]));
                if reverse {
                    analyzer.metadata.reverse();
                }
                assert_eq!(
                    canonical_identity_of(&analyzer, &unit).generic_arity,
                    expected
                );
            }
        }
    }

    #[test]
    fn nested_owner_rows_follow_supplied_declaration_tree() {
        use crate::analyzer::fq_name::{SegmentKind, segment_interner};
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path(), "example.py");
        let mut analyzer = MetadataAnalyzer::new(temp.path());
        // The indices are lexical parents, independent of identity depth.
        let tree = [
            ("p", None),
            ("Outer", Some(0)),
            ("Inner", Some(1)),
            ("member", Some(2)),
            ("sibling", Some(0)),
        ];
        for (index, (name, parent)) in tree.iter().enumerate() {
            let mut fq =
                parent.map_or_else(FqName::new, |parent| analyzer.units[parent].fq().clone());
            fq.push(segment_interner().intern(
                name,
                if index == 0 {
                    SegmentKind::Package
                } else {
                    SegmentKind::Type
                },
            ));
            analyzer.units.push(CodeUnit::from_fq(
                file.clone(),
                if index == 0 {
                    CodeUnitType::Module
                } else {
                    CodeUnitType::Class
                },
                fq,
                if index == 0 { 0 } else { 1 },
                None,
                false,
            ));
        }
        let expected = BTreeSet::from([
            ("Inner".to_owned(), "Outer".to_owned()),
            ("member".to_owned(), "Inner".to_owned()),
        ]);
        for reverse in [false, true] {
            if reverse {
                analyzer.units.reverse();
            }
            let mut rows = vec![];
            let mut reasons = vec![];
            let support = super::super::routes::IdentityRouteSupport::NONE
                .supported_relation(RouteHopKind::NestedOwner);
            declaration_relation_rows(&analyzer, &file, &support, &mut rows, &mut reasons);
            let actual = rows
                .iter()
                .filter(|row| row.kind == RouteHopKind::NestedOwner)
                .map(|row| {
                    let RouteEndpoint::Declaration(from) = &row.from else {
                        panic!("declaration")
                    };
                    let RouteEndpoint::Declaration(to) = &row.to else {
                        panic!("declaration")
                    };
                    (from.identifier().to_owned(), to.identifier().to_owned())
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn route_fanout_is_truncated_only_when_a_relation_is_omitted() {
        use crate::analyzer::fq_name::{SegmentKind, segment_interner};
        let temp = tempfile::tempdir().unwrap();
        let mut owner_fq = FqName::new();
        owner_fq.push(segment_interner().intern("Owner", SegmentKind::Type));
        let mut child_fq = owner_fq.clone();
        child_fq.push(segment_interner().intern("Child", SegmentKind::Type));
        for count in [
            MAX_ROUTE_FAN_OUT - 1,
            MAX_ROUTE_FAN_OUT,
            MAX_ROUTE_FAN_OUT + 1,
        ] {
            let mut analyzer = MetadataAnalyzer::new(temp.path());
            let child = CodeUnit::from_fq(
                ProjectFile::new(temp.path(), "child.py"),
                CodeUnitType::Class,
                child_fq.clone(),
                0,
                None,
                false,
            );
            analyzer.units.push(child.clone());
            let owners: BTreeSet<_> = (0..count)
                .map(|id| {
                    CodeUnit::from_fq(
                        ProjectFile::new(temp.path(), format!("owner{id}.py")),
                        CodeUnitType::Class,
                        owner_fq.clone(),
                        0,
                        None,
                        false,
                    )
                })
                .collect();
            analyzer.units.extend(owners.iter().cloned());
            let routes = identity_routes_from(
                &analyzer,
                &RouteEndpoint::Declaration(child),
                Some(&[RouteHopKind::NestedOwner]),
                &CancellationToken::default(),
            )
            .unwrap();
            let terminals: BTreeSet<_> = routes
                .iter()
                .filter_map(|route| route.terminal_declaration().cloned())
                .collect();
            assert_eq!(terminals.len(), count.min(MAX_ROUTE_FAN_OUT));
            assert!(terminals.is_subset(&owners));
            if count <= MAX_ROUTE_FAN_OUT {
                assert_eq!(terminals, owners);
            }
            assert_eq!(
                routes
                    .iter()
                    .filter(|route| route.termination == RouteTermination::FanOutTruncated)
                    .count(),
                usize::from(count > MAX_ROUTE_FAN_OUT)
            );
        }
    }
}
