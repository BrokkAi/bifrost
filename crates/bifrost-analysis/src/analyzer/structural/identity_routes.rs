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
//! for nested owners, and two analyzer capabilities (partial parts, abstract
//! member implementations) — plus one cycle-safe bounded traversal over the
//! rows, forward and inverse, so a round trip is checkable.
//!
//! The load-bearing properties are the sibling layers': grammar and language
//! knowledge stays behind adapter hooks and analyzer capabilities; endpoints
//! compare structurally (`CodeUnit` equality, never rendered names); and a
//! traversal that stops early says why (`RouteTermination`), never silently.

use super::facts::FileFacts;
use super::kinds::NormalizedKind;
use super::occurrence_rows::{OccurrenceRow, OccurrenceTarget, occurrences_for_file};
use super::occurrences::{Namespace, OccurrenceRole};
use super::routes::{CanonicalIdentity, IdentityAxis, RouteHopKind, RouteTermination};
use super::spec::StructuralSpec;
use crate::analyzer::common::language_for_file;
use crate::analyzer::structural_spec_for;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
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
/// when renderings disagree — a recorded absence (`Some(0)`) currently has no
/// producer, so a nongeneric declaration and an unrecorded one both project
/// `None` and compare equal on that field.
pub fn canonical_identity_of(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> CanonicalIdentity {
    let namespace = if unit.is_module() {
        Namespace::Module
    } else if unit.is_class() {
        Namespace::Type
    } else {
        Namespace::Value
    };
    let mut generic_arity: Option<u32> = None;
    for metadata in analyzer.signature_metadata(unit) {
        let parameters = metadata.type_parameters();
        if parameters.is_empty() {
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
    CanonicalIdentity::from_fq(
        language_for_file(unit.source()),
        namespace,
        unit.fq(),
        crate::analyzer::fq_name::segment_interner(),
        generic_arity,
    )
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
                note(
                    &mut reasons,
                    RouteRelationIncompleteReason::OccurrenceRowsIncomplete,
                );
            }
        }
        let facts = analyzer
            .structural_search_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(file));
        match facts {
            Some(facts) => site_relation_rows(
                spec,
                file,
                &facts,
                language,
                &occurrences.rows,
                support,
                &mut rows,
            ),
            None => note(
                &mut reasons,
                RouteRelationIncompleteReason::FactsUnavailable,
            ),
        }
        // Alias declarations (type aliases) also read the occurrence rows.
        if support.supports_relation(RouteHopKind::Alias) {
            type_alias_rows(analyzer, file, &occurrences.rows, &mut rows);
        }
    }

    declaration_relation_rows(analyzer, file, support, &mut rows);

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

fn note(reasons: &mut Vec<RouteRelationIncompleteReason>, reason: RouteRelationIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Import/export/re-export rows from resolved import-target occurrences, and
/// alias rows from import-alias tokens paired with the target of the same
/// import declaration.
fn site_relation_rows(
    spec: &dyn StructuralSpec,
    file: &ProjectFile,
    facts: &FileFacts,
    language: crate::analyzer::Language,
    occurrence_rows: &[OccurrenceRow],
    support: &super::routes::IdentityRouteSupport,
    rows: &mut Vec<RouteRelationRow>,
) {
    let tree = parse_tree_for_language(file, language, facts.source());

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

    for &(row, _, units) in &target_rows {
        let relation = tree
            .as_ref()
            .and_then(|tree| {
                tree.root_node()
                    .descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
            })
            .and_then(|token| spec.indirection_relation(token))
            .unwrap_or(RouteHopKind::Import);
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
/// partial parts, and abstract-member implementations.
fn declaration_relation_rows(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    support: &super::routes::IdentityRouteSupport,
    rows: &mut Vec<RouteRelationRow>,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        files: Vec<ProjectFile>,
        sources: Vec<String>,
    }

    impl Fixture {
        fn new(language: Language, files: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let mut project_files = Vec::new();
            let mut sources = Vec::new();
            for (relative_path, source) in files {
                let file = ProjectFile::new(root.clone(), *relative_path);
                file.write(source).expect("write fixture source");
                project_files.push(file);
                sources.push((*source).to_owned());
            }
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                files: project_files,
                sources,
            }
        }

        fn analyzer(&self) -> &dyn IAnalyzer {
            self.workspace.analyzer()
        }

        fn declaration(&self, fq_suffix: &str) -> CodeUnit {
            let mut all: Vec<CodeUnit> = self.analyzer().all_declarations().collect();
            all.retain(|unit| unit.fq_name().ends_with(fq_suffix));
            assert_eq!(
                all.len(),
                1,
                "expected exactly one declaration ending with {fq_suffix:?}, got {all:?}"
            );
            all.remove(0)
        }

        fn rows(&self, file_index: usize) -> RouteRelationsFileResult {
            route_relations_for_file(
                self.analyzer(),
                &self.files[file_index],
                &CancellationToken::new(),
            )
            .expect("not cancelled")
        }

        fn at(&self, file_index: usize, needle: &str) -> usize {
            self.sources[file_index]
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
        }
    }

    fn rows_of_kind(
        result: &RouteRelationsFileResult,
        kind: RouteHopKind,
    ) -> Vec<&RouteRelationRow> {
        result.rows.iter().filter(|row| row.kind == kind).collect()
    }

    /// Two declarations whose terminal spelling coincides but whose owner
    /// segments differ are different canonical identities; equality reads the
    /// structure, never the rendering.
    #[test]
    fn same_terminal_different_owner_decoys_compare_unequal() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/a/Map.java", "package a;\npublic class Map {}\n"),
                ("src/b/Map.java", "package b;\npublic class Map {}\n"),
            ],
        );
        let a_map = fixture.declaration("a.Map");
        let b_map = fixture.declaration("b.Map");
        let a_identity = canonical_identity_of(fixture.analyzer(), &a_map);
        let b_identity = canonical_identity_of(fixture.analyzer(), &b_map);
        assert_ne!(a_identity, b_identity);
        assert_eq!(
            a_identity.segments.last().unwrap().text,
            b_identity.segments.last().unwrap().text
        );
        assert_eq!(a_identity.namespace, Namespace::Type);
    }

    /// A C# partial type's parts group under one canonical identity: physical
    /// occurrences span both files.
    #[test]
    fn csharp_partial_parts_group_physically() {
        let fixture = Fixture::new(
            Language::CSharp,
            &[
                (
                    "src/WidgetA.cs",
                    "namespace App;\n\npublic partial class Widget {\n    public void A() {}\n}\n",
                ),
                (
                    "src/WidgetB.cs",
                    "namespace App;\n\npublic partial class Widget {\n    public void B() {}\n}\n",
                ),
            ],
        );
        let analyzer = fixture.analyzer();
        let mut widgets: Vec<CodeUnit> = analyzer
            .all_declarations()
            .filter(|unit| unit.is_class() && unit.fq_name().ends_with("Widget"))
            .collect();
        assert!(!widgets.is_empty(), "no Widget class declarations found");
        let widget = widgets.remove(0);
        let occurrences = physical_occurrences(analyzer, &widget);
        let files: std::collections::BTreeSet<&std::path::Path> = occurrences
            .iter()
            .map(|occurrence| occurrence.file.rel_path())
            .collect();
        assert!(
            files.len() >= 2,
            "expected parts in both files, got occurrences {occurrences:?}"
        );

        // And the partial-part relation rows point across parts.
        let rows = fixture.rows(0);
        let parts = rows_of_kind(&rows, RouteHopKind::PartialPart);
        assert!(
            !parts.is_empty(),
            "expected partial-part rows; rows: {:?}",
            rows.rows
        );
    }

    /// A Rust `pub use ... as ...` yields a re-export row for the target and
    /// an alias row for the local respelling, both site-anchored with the
    /// binder as provenance.
    #[test]
    fn rust_pub_use_yields_reexport_and_alias_rows() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub mod util {\n",
                    "    pub struct Widget;\n",
                    "}\n",
                    "pub use crate::util::Widget as W;\n",
                    "use crate::util::Widget;\n",
                    "pub fn build() -> Widget {\n",
                    "    Widget\n",
                    "}\n",
                ),
            )],
        );
        let rows = fixture.rows(0);

        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert_eq!(reexports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Declaration(target) = &reexports[0].to else {
            panic!("re-export target must be a declaration");
        };
        assert!(target.fq_name().ends_with("Widget"));

        let aliases = rows_of_kind(&rows, RouteHopKind::Alias);
        assert_eq!(aliases.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Site { name, range, .. } = &aliases[0].from else {
            panic!("an import alias is a site, not a declaration");
        };
        assert_eq!(name, "W");
        assert_eq!(range.start_byte, fixture.at(0, "W;"));

        let imports = rows_of_kind(&rows, RouteHopKind::Import);
        assert_eq!(imports.len(), 1, "rows: {:?}", rows.rows);
    }

    /// A Rust type-alias chain traverses hop by hop to the origin struct, and
    /// a mutual alias cycle terminates as an explicit cycle, not an answer.
    #[test]
    fn rust_type_alias_chain_traverses_and_cycles_stay_explicit() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub struct Widget;\n",
                    "pub type A = Widget;\n",
                    "pub type B = A;\n",
                ),
            )],
        );
        let b = fixture.declaration("B");
        let routes = identity_routes_from(
            fixture.analyzer(),
            &RouteEndpoint::Declaration(b),
            None,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        let terminal: Vec<_> = routes
            .iter()
            .filter(|route| route.termination == RouteTermination::Terminal)
            .collect();
        assert_eq!(terminal.len(), 1, "routes: {routes:?}");
        assert_eq!(terminal[0].hops.len(), 2, "routes: {routes:?}");
        assert!(
            terminal[0]
                .terminal_declaration()
                .expect("terminal declaration")
                .fq_name()
                .ends_with("Widget")
        );
        assert!(
            terminal[0]
                .hops
                .iter()
                .all(|hop| hop.kind == RouteHopKind::Alias)
        );

        let cyclic = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!("pub type A = B;\n", "pub type B = A;\n"),
            )],
        );
        let a = cyclic.declaration("A");
        let routes = identity_routes_from(
            cyclic.analyzer(),
            &RouteEndpoint::Declaration(a),
            None,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        assert!(
            routes
                .iter()
                .any(|route| route.termination == RouteTermination::Cycle),
            "routes: {routes:?}"
        );
        assert!(
            routes
                .iter()
                .all(|route| route.termination != RouteTermination::Terminal),
            "a cycle must not also read as a terminal answer: {routes:?}"
        );
    }

    /// A Rust trait member points at its implementing member through the
    /// implementation relation.
    #[test]
    fn rust_trait_member_implementation_rows() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub trait Runner {\n",
                    "    fn run(&self);\n",
                    "}\n",
                    "pub struct App;\n",
                    "impl Runner for App {\n",
                    "    fn run(&self) {}\n",
                    "}\n",
                ),
            )],
        );
        let rows = fixture.rows(0);
        let implementations = rows_of_kind(&rows, RouteHopKind::Implementation);
        assert!(
            !implementations.is_empty(),
            "expected implementation rows; rows: {:?}",
            rows.rows
        );
    }

    /// A nested declaration projects onto its owner through the nested-owner
    /// relation, structurally (FqName parent equality), never by rendering.
    #[test]
    fn java_nested_owner_rows() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Outer.java",
                concat!(
                    "public class Outer {\n",
                    "    public class Inner {}\n",
                    "}\n",
                ),
            )],
        );
        let rows = fixture.rows(0);
        let owners = rows_of_kind(&rows, RouteHopKind::NestedOwner);
        let inner_to_outer = owners.iter().any(|row| {
            matches!(
                (&row.from, &row.to),
                (RouteEndpoint::Declaration(from), RouteEndpoint::Declaration(to))
                    if from.fq_name().ends_with("Inner") && to.fq_name().ends_with("Outer")
            )
        });
        assert!(inner_to_outer, "rows: {:?}", rows.rows);
    }

    /// A JS facade that imports a name and exports it produces an export
    /// row whose target is the origin declaration in the other file — the
    /// resolver follows the local import binding across files. The
    /// single-statement `export ... from` form resolves to nothing today (a
    /// resolver gap the adapter's unclaimed re-export relation records), so
    /// this fixture pins the two-statement facade shape.
    #[test]
    fn js_export_of_imported_name_reaches_the_origin() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[
                (
                    "index.js",
                    "import { widget } from './widget.js';\nexport { widget };\n",
                ),
                ("widget.js", "export function widget() { return 1; }\n"),
            ],
        );
        let rows = fixture.rows(0);
        let exports = rows_of_kind(&rows, RouteHopKind::Export);
        assert_eq!(exports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Declaration(target) = &exports[0].to else {
            panic!("export target must be a declaration");
        };
        assert_eq!(target.source(), &fixture.files[1]);
        assert!(
            !rows.completeness.covers(RouteHopKind::ReExport),
            "the unclaimed re-export relation must not read as covered"
        );
    }

    /// The forward/inverse round trip holds for a re-export site: forward
    /// reaches the origin declaration, and inverse enumeration over the same
    /// scope reaches the site back.
    #[test]
    fn round_trip_holds_for_rust_reexport_site() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub mod util {\n",
                    "    pub struct Widget;\n",
                    "}\n",
                    "pub use crate::util::Widget;\n",
                ),
            )],
        );
        let rows = fixture.rows(0);
        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert_eq!(reexports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Site { file, range, name } = &reexports[0].from else {
            panic!("re-export site expected");
        };
        let outcome = round_trip_from_site(
            fixture.analyzer(),
            file,
            *range,
            name,
            &fixture.files,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        let RoundTripOutcome::Holds { terminals } = outcome else {
            panic!("round trip must hold, got {outcome:?}");
        };
        assert!(terminals[0].fq_name().ends_with("Widget"));
    }
}
