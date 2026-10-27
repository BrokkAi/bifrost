//! One endpoint's finite crate-row plan. Nothing here is retained by a selection.
use super::super::demand_closure::{
    ClosureTag, ExportHydration, HalfBoundary, HalfObservation, PlacementFacts, PlacementStart,
    Read, RouteLocation, StartSelection, WalkCursor,
};
use super::super::rust_crate_context::{self as sql, Module};
use super::super::rust_crate_rows::{RustCrateDeclaration, RustCrateRows};
use super::super::rust_prefix::resolve_rust_type_prefix;
use super::super::*;
use crate::analyzer::resolution::DemandReferenceKey;
use crate::analyzer::resolution::{FactResolutionAnswer, mounted_site_node};
use crate::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION;
use rusqlite::{OptionalExtension, params};

pub(crate) type RowRootPlan = super::super::demand_closure::RootFrame;

pub(super) struct EndpointRows<'a, 'store, 'input> {
    pub(super) ready: &'a ReadySelectedResolution<'store, 'input>,
    pub(super) base: &'a dyn BatchResolutionFragmentSource,
    pub(super) cancellation: &'a CancellationToken,
    pub(super) session: &'a ResolutionSession,
    pub(super) topologies: &'a [i64],
}

impl<'a, 'store> EndpointRows<'a, 'store, '_> {
    fn mount_table(&self) -> SelectedMountTable<'a, 'store> {
        SelectedMountTable::new(&self.ready.inventory)
    }

    /// Read one certified owner at a time; shared code schedules the lexical
    /// chain. These recursive module-target projections remain temporary
    /// private authorities until the context producer publishes direct rows.
    fn route_starts(
        &self,
        module: &Module,
        scope: ResolutionScopeId,
        name: &str,
    ) -> Result<StartSelection> {
        let conn = self.ready.inventory.connection();
        // A source prefix with a selected dependency root already has a
        // certified start outside the requester's lexical owner. Its proof
        // must not inherit that owner's unrelated open module inventory.
        // Likewise, structural module anchors never look up a lexical binder.
        if sql::is_module_anchor(name) {
            let recipe = ResolutionLookupSemanticRecipe::new(
                Language::Rust,
                ResolutionNamespace::Type,
                name,
            );
            return Ok(StartSelection {
                locations: vec![
                    RouteLocation::Container {
                        unit: module.topology,
                        container: module.path.clone(),
                    }
                    .into(),
                ],
                scopes: Vec::new(),
                blocks_fallback: true,
                head: Some(recipe),
                lexical: None,
                providers: Vec::new(),
            });
        }
        let dependencies = conn
            .prepare_cached(sql::DEPENDENCY.as_str())?
            .query_map(
                params![module.topology, name, RUST_UNIT_SUMMARY_DERIVATION_VERSION],
                |row| Ok((row.get::<_, i64>(0)?, "crate".to_owned())),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !dependencies.is_empty() {
            return Ok(super::super::demand_closure::LexicalRouteStarts {
                starts: dependencies
                    .into_iter()
                    .map(|(unit, container)| RouteLocation::Container { unit, container }.into())
                    .collect(),
                scopes: Vec::new(),
                blocks_fallback: true,
                providers: Vec::new(),
            }
            .into());
        }
        Ok(StartSelection {
            locations: Vec::new(),
            scopes: Vec::new(),
            blocks_fallback: false,
            head: None,
            providers: Vec::new(),
            lexical: Some(super::super::demand_closure::LexicalStartRequest {
                scope,
                lookup: ResolutionLookupSemanticRecipe::new(
                    Language::Rust,
                    ResolutionNamespace::Type,
                    name,
                ),
            }),
        })
    }

    /// The module placements a root half of `fragment` is asked in, and the
    /// incompleteness of a file outside the request's selected Cargo graph.
    ///
    /// Such a file is placed only in crates the request is not made on
    /// behalf of: a dependency's file, reached by a lookup the request
    /// demanded there (an impl header's trait path, say). Its root anchor
    /// names its own crate, which this request compiles no route for, so the
    /// half has no answer here and says so. Leaving it unasked made the
    /// lookup a complete absence.
    fn modules(&self, fragment: BindingFragmentId) -> Result<(Vec<Module>, ResolutionCompletion)> {
        let mount = self
            .mount_table()
            .mount_for_fragment(fragment)?
            .expect("source-issued fragment belongs to selection");
        let modules = (RustCrateRows { ready: self.ready }).modules_for_mount(
            self.mount_table(),
            mount.ordinal(),
            self.topologies,
            self.cancellation,
        )?;
        // Preserve distinct target roots for a file shared by Cargo targets.
        // A dependency's placement cannot answer `crate::` from the requester's
        // source, even when that dependency contains the same file.
        let (asked, outside): (Vec<_>, Vec<_>) =
            modules.into_iter().partition(|module| module.requested);
        let completion = match (asked.is_empty(), outside.as_slice()) {
            (true, [first, ..]) => sql::placed_outside_request_crates(
                &self.ready.context_identities,
                &first.rel_path,
                outside.iter().map(|module| module.topology),
            ),
            _ => ResolutionCompletion::Complete,
        };
        Ok((asked, completion))
    }

    /// The export halves one target name reaches, each with its demand and
    /// its evidence, and the incompleteness of the exports this request could
    /// not reach: a crate-declared macro item whose invoking file the request
    /// did not stage.
    #[allow(clippy::type_complexity)]
    fn exports(
        &self,
        module: &Module,
        target: (i64, String, String),
        demand: &ResolutionLookupSemanticRecipe,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        let rows = RustCrateRows { ready: self.ready };
        // An admitted alias endpoint can coexist with an open or ambiguous
        // source binding. Finding its declaration does not close that source.
        let binding_inventory = rows.crate_binding_inventory(
            module,
            target.0,
            &target.1,
            sql::namespace(demand.namespace()),
            &target.2,
        )?;
        let completion = completion.combine(&binding_inventory.completion);
        let mut exports = rows.crate_exports_from_inventory(
            module,
            target.0,
            &target.1,
            sql::namespace(demand.namespace()),
            &target.2,
            &binding_inventory,
        )?;
        exports.sort_unstable();
        exports.dedup();
        use super::super::demand_closure::{ExportDeclaration, export_definitions};
        enum MissingDeclaration {
            Unlowered {
                path: String,
                site: u32,
            },
            Unstaged {
                blob: i64,
                declaration: i64,
                module: bool,
            },
        }
        let declarations = exports.into_iter().map(|export| {
            let mount = self.mount_table().mount_by_ordinal(export.mount)?;
            Ok(match export.declaration {
                RustCrateDeclaration::Site(site) => (
                    ExportDeclaration::SelectedSite {
                        semantic: crate::analyzer::resolution::mounted_site_semantic(
                            mount.fragment(),
                            ResolutionSiteId::new(site),
                        ),
                        node: mounted_site_node(mount.fragment(), ResolutionSiteId::new(site)),
                    },
                    MissingDeclaration::Unlowered {
                        path: mount.persisted_relative_path().to_owned(),
                        site,
                    },
                ),
                RustCrateDeclaration::MacroItem(declaration) => {
                    let (start, end, module) = self
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(sql::MACRO_ITEM_NAME_RANGE)?
                        .query_row(params![export.blob, declaration], |row| {
                            Ok((
                                row.get::<_, usize>(0)?,
                                row.get::<_, usize>(1)?,
                                row.get::<_, bool>(2)?,
                            ))
                        })?;
                    (
                        ExportDeclaration::GeneratedRange {
                            mount: export.mount,
                            start,
                            end,
                        },
                        MissingDeclaration::Unstaged {
                            blob: export.blob,
                            declaration,
                            module,
                        },
                    )
                }
            })
        });
        let Some((definitions, unstaged)) = export_definitions(
            self.session,
            self.ready,
            self.base,
            self.cancellation,
            declarations,
            |missing| {
                Ok(match missing {
                    MissingDeclaration::Unlowered { path, site } => {
                        sql::unlowered_export_declaration(
                            &self.ready.context_identities,
                            &path,
                            site,
                        )
                    }
                    MissingDeclaration::Unstaged {
                        blob,
                        declaration,
                        module,
                    } => sql::unstaged_macro_item(
                        &self.ready.context_identities,
                        blob,
                        declaration,
                        module,
                    ),
                })
            },
        )?
        else {
            return Ok(None);
        };
        super::super::demand_closure::hydrate_exports(
            self.session,
            self.ready,
            self.base,
            self.cancellation,
            definitions,
            demand.namespace(),
            &completion,
            unstaged,
        )
    }
}

/// Every crate-row name that reaches one exported declaration.
///
/// The seed is the declaration's own source site in one export namespace; the
/// caller certifies its namespace from canonical root export halves. The
/// selected declaration supplies its current name and module authority; its
/// selected mount supplies placement. The recursion then follows
/// re-export routes, glob re-exports and imports over the crate rows.
pub(super) const REVERSE_EXPORTED_NAMES: &str = "WITH RECURSIVE names(topology_id, summary_id, unit_key, module_path, namespace, name) AS (
 SELECT placement.topology_id, owner.summary_id, owner.unit_key,
        CASE WHEN properties.macro_exported=1 THEN 'crate'
             WHEN properties.declaration_kind=9 THEN placement.container_path || '::' || enum_unit.identifier
             ELSE placement.container_path END,
        ?3, unit.identifier
 FROM selected_resolution_mounts AS mount
 CROSS JOIN resolution_semantic_sites AS site
  ON site.blob_id=mount.blob_id AND site.source_site=?2 AND site.semantic_role='definition'
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=site.blob_id AND authority.semantic_key=site.semantic_key
 CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id=authority.blob_id AND mapping.declaration_id=authority.declaration
 CROSS JOIN code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=authority.blob_id AND properties.declaration_id=authority.declaration
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.topology_id=placement.topology_id
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=owner.summary_id
 LEFT JOIN resolution_member_owner_properties AS member
  ON member.blob_id=authority.blob_id AND member.definition_semantic_key=authority.semantic_key
 LEFT JOIN resolution_rust_declaration_authorities AS enum_authority
  ON enum_authority.blob_id=member.blob_id AND enum_authority.semantic_key=member.owner_definition_semantic_key
 LEFT JOIN source_declaration_units AS enum_mapping
  ON enum_mapping.blob_id=enum_authority.blob_id AND enum_mapping.declaration_id=enum_authority.declaration
 LEFT JOIN code_units AS enum_unit
  ON enum_unit.blob_id=enum_mapping.blob_id AND enum_unit.unit_key=enum_mapping.unit_key
 WHERE mount.mount_ordinal=?4 AND mount.blob_id=?1
  AND ((properties.nearest_declaration_boundary=0 AND properties.declaration_kind NOT IN (8,9,14))
       OR (properties.declaration_kind=9 AND enum_unit.identifier IS NOT NULL))
  AND cr_cfg(properties.cfg_condition,json(context.cfg_atoms))=1
 UNION
 SELECT owner.topology_id, route.summary_id, owner.unit_key,
        route.module_path, names.namespace, route.bound_name
 FROM names
 CROSS JOIN selected_rust_unit_summaries AS target ON target.summary_id=names.summary_id
 CROSS JOIN rust_resolution_unit_summary_reexport_routes AS route
  INDEXED BY rust_resolution_unit_summary_reexport_routes_target_identity
  ON route.target_unit_key=target.unit_key
 AND route.target_module_path=names.module_path AND route.target_name=names.name
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=route.summary_id
 UNION
 SELECT owner.topology_id, route.summary_id, owner.unit_key,
        route.module_path, names.namespace, names.name
 FROM names
 CROSS JOIN selected_rust_unit_summaries AS target ON target.summary_id=names.summary_id
 CROSS JOIN rust_resolution_unit_summary_glob_reexport_routes AS route
  INDEXED BY rust_resolution_unit_summary_glob_reexport_routes_target_identity
  ON route.target_unit_key=target.unit_key
 AND route.target_module_path=names.module_path
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=route.summary_id
 UNION
 SELECT owner.topology_id, imports.summary_id, owner.unit_key,
        imports.module_path, names.namespace, imports.bound_name
 FROM names
 CROSS JOIN selected_rust_unit_summaries AS target ON target.summary_id=names.summary_id
 CROSS JOIN rust_resolution_unit_summary_import_routes AS imports
  INDEXED BY rust_resolution_unit_summary_import_routes_target_identity
  ON imports.target_unit_key=target.unit_key
 AND imports.target_module_path=names.module_path
 AND imports.target_name=names.name AND imports.namespace=names.namespace
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=imports.summary_id
) SELECT DISTINCT namespace, name FROM names";

pub(crate) struct RustHalfRows<'a, 'store, 'input> {
    rows: EndpointRows<'a, 'store, 'input>,
    source: &'a super::super::demand_closure::SourceHalf,
    plan: &'a RowRootPlan,
    scope_ordinals: &'a crate::analyzer::store::resolution_lexical::NodeSourceScopes,
    lexical: &'a dyn super::super::demand_closure::HalfSource,
    modules: Vec<Module>,
    resolved: Option<super::super::rust_prefix::RustQualifiedPrefixResolution>,
    source_completion: ResolutionCompletion,
    known_prefix: bool,
    import_root_name: Option<String>,
    root_names_a_workspace_crate: bool,
    external_root_bindings: Vec<SemanticId>,
    external_type_import_scopes: Vec<(i64, u32)>,
    prefix_spelling: Option<String>,
    prefix_kind: super::super::rust_crate_context::RoutePrefixKind,
    local_type_prefix_is_decided: bool,
    prefix_scope: BindingNodeId,
    placed_topologies: Vec<i64>,
    prefix_has_no_placements: bool,
    fallback_name: Option<String>,
}
impl<'a, 'store, 'input> EndpointRows<'a, 'store, 'input> {
    pub(super) fn half(
        self,
        source: &'a super::super::demand_closure::SourceHalf,
        plan: &'a RowRootPlan,
        scope_ordinals: &'a crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        lexical: &'a dyn super::super::demand_closure::HalfSource,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<RustHalfRows<'a, 'store, 'input>> {
        let conn = self.ready.inventory.connection();
        let identity = source.identity;
        let scope = source.scope;
        let prefix = source.prefix;
        let prefix_scope_head = source.prefix_scope_head;
        let route = &source.route;
        let demand = &source.demand;
        let resolved = prefix.map(|prefix| {
            let (_, answer) = inputs
                .iter()
                .find(|(reference, _)| *reference == DemandReferenceKey::caller(prefix))
                .expect("scheduler supplies every prefix");
            resolve_rust_type_prefix(answer)
        });
        // Placements are alternative justifications for one canonical
        // export. Close their evidence before issuing its immutable cell.
        let mut pending_completion = ResolutionCompletion::Complete;
        let mut known_prefix = false;
        // An import half with no route segments names the path root
        // itself: `use serde as s;` and `use serde::{self as s};` bind `s`
        // to the crate that `serde` names, which in Rust 2018 is an entry
        // of the extern prelude. The half's own stack spells the demand,
        // which an alias renames, so the root's spelling is the import
        // fact's target name, the same relation the import-gap join below
        // reads. A route with segments already carries the root in
        // `route[0]`.
        let import_root_name = None;
        // Both are the half's, not one module placement's. A file this
        // fragment's modules place more than once asks the route-head
        // question once per placement, and only the placement whose
        // topology declares the dependency can bind the root; claiming the
        // boundary per placement said a workspace crate left the
        // workspace. The graph route's copy of this guard says the same
        // thing (`rust_crate_context.rs`), and the two must not drift.
        let root_names_a_workspace_crate = false;
        let external_root_bindings = Vec::new();
        let external_type_import_scopes = Vec::new();
        let prefix_spelling = if let Some(prefix) = prefix {
            self.ready
                .rust_prefix_spellings(&self.ready.lexical_source(), &[prefix], self.cancellation)?
                .remove(&prefix)
        } else {
            None
        };
        let prefix_kind = if prefix.is_some() && route.is_empty() {
            let resolved = resolved.as_ref().expect("a prefix has a resolution");
            super::super::rust_crate_context::route_prefix_kind(
                self.ready,
                prefix_spelling.as_deref(),
                &resolved.targets,
                &resolved.completion,
            )?
        } else {
            super::super::rust_crate_context::RoutePrefixKind::Other
        };
        let local_type_prefix_is_decided = if route.is_empty() {
            prefix_kind == super::super::rust_crate_context::RoutePrefixKind::BlockLocalType
        } else {
            match &resolved {
                Some(resolved) => {
                    super::super::rust_crate_context::block_local_type_prefix_binding_is_decided(
                        self.ready,
                        &resolved.targets,
                        &resolved.completion,
                    )?
                }
                None => false,
            }
        };
        let (modules, outside_request) = self.modules(identity.fragment())?;
        pending_completion = pending_completion.combine(&outside_request);
        let prefix_scope = prefix_scope_head
            .filter(|scope_head| {
                scope_ordinals
                    .get(scope_head)
                    .expect("prefix lexical scope was batched")
                    .is_some()
            })
            .unwrap_or(scope);
        if prefix.is_some() || route.is_empty() {
            let prefix_mount = prefix.and_then(|prefix| prefix.ordinal()).or(self
                .mount_table()
                .mount_for_fragment(identity.fragment())?
                .map(|mount| mount.ordinal().get()));
            let generated_surface =
                super::super::rust_crate_context::generated_surface_prefix_boundary(
                    conn,
                    &self.ready.context_identities,
                    &modules,
                    prefix_mount,
                    Some(prefix_spelling.as_deref().unwrap_or(demand.spelling())),
                    route,
                )?;
            if generated_surface != ResolutionCompletion::Complete {
                known_prefix = true;
                pending_completion = pending_completion.combine(&generated_surface);
            }
        }
        let placed_topologies = modules
            .iter()
            .map(|module| module.topology)
            .collect::<Vec<_>>();
        Ok(RustHalfRows {
            rows: self,
            source,
            plan,
            scope_ordinals,
            lexical,
            modules,
            resolved,
            source_completion: pending_completion,
            known_prefix,
            import_root_name,
            root_names_a_workspace_crate,
            external_root_bindings,
            external_type_import_scopes,
            prefix_spelling,
            prefix_kind,
            local_type_prefix_is_decided,
            prefix_scope,
            placed_topologies,
            prefix_has_no_placements: false,
            fallback_name: None,
        })
    }
}
impl super::super::demand_closure::HalfRules for RustHalfRows<'_, '_, '_> {
    type MemberRow = ();
    type Rank = (u32, u32);
    type Provider = ();
    type LexicalTiers =
        std::iter::Once<super::super::demand_closure::LexicalStartTier<Self::Rank, ()>>;
    type Placement = Module;
    type Target = (i64, String, String);
    type Member = (i64, u32, String);
    fn placements(&mut self) -> Vec<Module> {
        std::mem::take(&mut self.modules)
    }
    fn prefix_has_targets(&self) -> bool {
        self.resolved
            .as_ref()
            .is_some_and(|resolved| !resolved.targets.is_empty())
    }
    fn language(&self) -> Language {
        Language::Rust
    }
    fn initial_completion(&self) -> ResolutionCompletion {
        self.source_completion.clone()
    }
    fn placement(&self, module: &Module, tag: ClosureTag) -> Option<PlacementFacts<Self::Target>> {
        if !self.source.is_import
            && !self.lexical.node_is_scope_head_in(
                self.scope_ordinals,
                self.source.scope,
                module.fragment,
                module.scope,
            )
        {
            return None;
        }
        Some(PlacementFacts {
            tag,
            completion: module.overlay_completion.combine(&self.plan.completion),
            targets: Vec::new(),
            members: Vec::new(),
        })
    }
    fn root_starts(
        &mut self,
        module: &Module,
        facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Vec<PlacementStart<Self::Member>>> {
        let conn = self.rows.ready.inventory.connection();
        let lexical = self.lexical;
        let demand = &self.source.demand;
        let route = &self.source.route;
        let mut starts = Vec::new();
        if let Some(resolved) = &self.resolved {
            if !self.local_type_prefix_is_decided {
                facts.completion = facts.completion.combine(&resolved.completion);
            }
            let mut prefix_starts = Vec::new();
            for target in &resolved.targets {
                if self
                    .rows
                    .base
                    .lookup_definition_node(*target, self.rows.cancellation)?
                    .is_none()
                {
                    continue;
                }
                let Some(crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(
                    provenance,
                )) = lexical.semantic_provenance(*target, self.rows.cancellation)?
                else {
                    continue;
                };
                let starts = conn
                    .prepare_cached(PREFIX_MODULES)?
                    .query_map(
                        params![
                            provenance.mount().ordinal().get(),
                            provenance.local_key().get(),
                            module.topology
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<String>>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, u32>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                prefix_starts.extend(starts);
            }
            self.known_prefix |= !prefix_starts.is_empty();
            self.prefix_has_no_placements = prefix_starts.is_empty();
            if prefix_starts
                .iter()
                .any(|(_, path, _, _, _)| path.is_some())
                && prefix_starts
                    .iter()
                    .any(|(_, path, _, _, _)| path.is_none())
            {
                let rel_path = self
                    .rows
                    .mount_table()
                    .mount_for_fragment(self.source.identity.fragment())?
                    .map(|mount| mount.persisted_relative_path().to_owned());
                let prefix_spelling = self
                    .rows
                    .ready
                    .rust_prefix_spellings(
                        &self.rows.ready.lexical_source(),
                        &[self.source.prefix.expect("a mixed prefix exists")],
                        self.rows.cancellation,
                    )?
                    .into_values()
                    .next();
                facts.completion =
                    facts
                        .completion
                        .combine(&super::super::rust_crate_context::route_dead_end(
                            &self.rows.ready.context_identities,
                            super::super::rust_crate_context::RouteDeadEnd::MixedRoutePrefix,
                            rel_path.as_deref(),
                            prefix_spelling.as_deref(),
                            None,
                            route,
                            demand,
                        ));
            }
            for (id, path, subject_blob, subject_site, subject_path) in prefix_starts {
                if let Some(path) = path {
                    starts.push(PlacementStart::Route {
                        rank: None,
                        scope: None,
                        cursor: WalkCursor::container(facts.tag, id, path, route.len().min(1)),
                        anchor: ResolutionRootImportAnchor::Lexical,
                    });
                } else if route.is_empty() {
                    starts.push(PlacementStart::Member((
                        subject_blob,
                        subject_site,
                        subject_path,
                    )));
                }
            }
        }
        Ok(starts)
    }
    fn route_rules<'a>(
        &'a self,
        module: &'a Module,
        anchor: ResolutionRootImportAnchor,
        route: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl super::super::demand_closure::RouteRules<ClosureTag> + 'a {
        super::super::rust_crate_rows::RustRouteRules {
            rows: RustCrateRows {
                ready: self.rows.ready,
            },
            requester: module,
            anchor,
            route,
        }
    }
    fn route_target(
        &self,
        location: RouteLocation,
        _: Option<&Self::Rank>,
        _: Option<ResolutionScopeId>,
    ) -> Self::Target {
        let RouteLocation::Container { unit, container } = location else {
            unreachable!("Rust module route returns a container")
        };
        (unit, container, self.source.demand.spelling().to_owned())
    }
    fn target_location(&self, target: &Self::Target) -> RouteLocation {
        RouteLocation::Container {
            unit: target.0,
            container: target.1.clone(),
        }
    }
    fn member_bridges(
        &self,
        module: &Module,
        (blob, site, path): Self::Member,
        completion: &ResolutionCompletion,
    ) -> Result<Vec<SelectedRootBridgeDescriptor>> {
        RustCrateRows {
            ready: self.rows.ready,
        }
        .crate_trait_member_bridges(
            &self.rows.mount_table(),
            module,
            self.source.identity.fragment(),
            self.source.token,
            self.source.anchor,
            self.source.anchor_semantic,
            self.source
                .prefix
                .expect("a member start has a resolved prefix"),
            &self.source.demand,
            blob,
            site,
            &path,
            completion,
            self.rows.cancellation,
        )
    }
    fn prefix_selection(
        &mut self,
        module: &Module,
        _facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection>> {
        if self.resolved.is_none()
            || !((self.prefix_has_no_placements && !self.prefix_kind.is_type())
                || self.source.anchor == ResolutionRootImportAnchor::Absolute)
        {
            return Ok(None);
        }
        self.fallback_name = None;
        if self.source.anchor == ResolutionRootImportAnchor::Absolute {
            return Ok(Some(StartSelection {
                locations: vec![
                    RouteLocation::Container {
                        unit: module.topology,
                        container: "crate".to_owned(),
                    }
                    .into(),
                ],
                scopes: Vec::new(),
                blocks_fallback: true,
                head: None,
                lexical: None,
                providers: Vec::new(),
            }));
        }
        let prefix = self.source.prefix.expect("resolved prefix");
        let names = self.rows.ready.rust_prefix_spellings(
            &self.rows.ready.lexical_source(),
            &[prefix],
            self.rows.cancellation,
        )?;
        let Some(name) = names.get(&prefix) else {
            return Ok(None);
        };
        self.fallback_name = Some(name.clone());
        self.root_names_a_workspace_crate |= self
            .rows
            .ready
            .inventory
            .connection()
            .prepare_cached(sql::DEPENDENCY.as_str())?
            .exists(params![
                module.topology,
                name,
                RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ])?;
        let scope = self
            .scope_ordinals
            .get(&self.prefix_scope)
            .copied()
            .flatten()
            .filter(|(fragment, _)| *fragment == module.fragment)
            .map_or(module.scope, |(_, scope)| scope);
        Ok(Some(self.rows.route_starts(module, scope, name)?))
    }
    fn prefix_starts(
        &mut self,
        module: &Module,
        mut selected: StartSelection,
        facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Vec<PlacementStart<Self::Member>>> {
        let conn = self.rows.ready.inventory.connection();
        let mut starts = Vec::new();
        let name = self.fallback_name.clone();
        if let Some(name) = name.as_deref() {
            let blocks_fallback = selected.blocks_fallback;
            let prefix_import_scopes = std::mem::take(&mut selected.scopes);
            starts.extend(selected.into_containers());
            if !blocks_fallback {
                // A module an item macro declares in this module
                // has no lexical binder, so the prefix found
                // nothing lexically; the crate row places it.
                for row in conn
                    .prepare_cached(sql::NAMED_MACRO_MODULE)?
                    .query_map(params![module.topology, module.path, name], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })?
                {
                    starts.push(row?);
                }
            }
            if starts.is_empty() {
                let mut details = Vec::new();
                for binder_scope in &prefix_import_scopes {
                    details.extend(
                        super::super::rust_crate_context::macro_gated_import_route_details(
                            conn,
                            module,
                            name,
                            *binder_scope,
                        )?,
                    );
                }
                if details.is_empty() && module.unmounted {
                    details.extend(
                        super::super::rust_crate_context::macro_gated_unmounted_file_details(
                            conn,
                            &module.rel_path,
                        )?,
                    );
                }
                if !details.is_empty() {
                    self.known_prefix = true;
                    facts.completion = facts.completion.combine(
                        &super::super::rust_crate_context::macro_gated_route_boundary(
                            &self.rows.ready.context_identities,
                            &details,
                        ),
                    );
                } else if module.unmounted {
                    let details =
                        super::super::rust_crate_context::inactive_cfg_unmounted_file_details(
                            conn,
                            &module.rel_path,
                        )?;
                    if !details.is_empty() {
                        self.known_prefix = true;
                        facts.completion = facts.completion.combine(
                            &super::super::rust_crate_context::inactive_cfg_route_boundary(
                                &self.rows.ready.context_identities,
                                &details,
                            ),
                        );
                    }
                }
            }
        } else {
            starts.extend(selected.into_containers());
        }
        self.known_prefix |= !starts.is_empty();
        Ok(starts
            .into_iter()
            .map(|(id, path)| PlacementStart::Route {
                rank: None,
                scope: None,
                cursor: WalkCursor::container(facts.tag, id, path, 0),
                anchor: self.source.anchor,
            })
            .collect())
    }
    fn import_targets(
        &mut self,
        module: &Module,
        facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<bool>> {
        let conn = self.rows.ready.inventory.connection();
        let lexical = self.lexical;
        let demand = &self.source.demand;
        let route = &self.source.route;
        if self.resolved.is_some() || !self.source.is_import {
            return Ok(Some(true));
        }
        let mut matched_scope = false;
        for raw in (RustCrateRows {
            ready: self.rows.ready,
        })
        .module_import_scopes(module.blob, module.scope.get())?
        {
            if self.rows.cancellation.is_cancelled() {
                return Ok(None);
            }
            if !lexical.node_is_scope_head_in(
                self.scope_ordinals,
                self.source.scope,
                module.fragment,
                ResolutionScopeId::new(raw),
            ) {
                continue;
            }
            matched_scope = true;
            if demand.namespace() == ResolutionNamespace::Type {
                self.external_type_import_scopes.push((module.blob, raw));
            }
            if route.is_empty() && self.import_root_name.is_none() {
                self.import_root_name = conn
                    .prepare_cached(sql::IMPORT_ROOT_NAME)?
                    .query_row(params![module.blob, raw, demand.spelling()], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?;
            }
            for row in conn.prepare_cached(sql::NAMED)?.query_map(
                params![
                    module.topology,
                    module.path,
                    module.blob,
                    raw,
                    demand.spelling(),
                    sql::namespace(demand.namespace()),
                    if module.overlay_completion == ResolutionCompletion::Complete {
                        module.selected_blob
                    } else {
                        module.blob
                    }
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )? {
                let (key, path, name) = row?;
                match sql::selected_crate_topology(conn, &key)? {
                    Some(id) => facts.targets.push((id, path, name)),
                    None => {
                        facts.completion =
                            facts.completion.combine(&sql::unselected_target_boundary(
                                &self.rows.ready.context_identities,
                                &key,
                            ));
                    }
                }
            }
            for row in conn.prepare_cached(sql::GLOBS)?.query_map(
                params![module.topology, module.path, module.blob, raw],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )? {
                let (key, path, segments) = row?;
                let segments: Vec<String> = serde_json::from_str(&segments)
                    .map_err(|error| StoreError::corrupt(error.to_string()))?;
                if !segments
                    .iter()
                    .map(String::as_str)
                    .eq(route.iter().map(|recipe| recipe.spelling()))
                {
                    continue;
                }
                match sql::selected_crate_topology(conn, &key)? {
                    Some(id) => {
                        facts.targets.push((id, path, demand.spelling().to_owned()));
                    }
                    None => {
                        facts.completion =
                            facts.completion.combine(&sql::unselected_target_boundary(
                                &self.rows.ready.context_identities,
                                &key,
                            ));
                    }
                }
            }
        }
        if !matched_scope && facts.completion == ResolutionCompletion::Complete {
            return Ok(Some(false));
        }
        Ok(Some(true))
    }
    fn canonical_targets(
        &self,
        module: &Module,
        facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<Vec<Self::Target>>> {
        let lexical = self.lexical;
        let rows = RustCrateRows {
            ready: self.rows.ready,
        };
        let demand = &self.source.demand;
        let in_module_scope = lexical.node_is_scope_head_in(
            self.scope_ordinals,
            self.source.scope,
            module.fragment,
            module.scope,
        );
        let mut binding_targets = None;
        if self.source.is_import
            && self.source.prefix.is_none()
            && let Some((fragment, owner_scope)) = self
                .scope_ordinals
                .get(&self.source.scope)
                .copied()
                .flatten()
            && fragment == module.fragment
        {
            let inventory = if in_module_scope {
                rows.crate_import_inventory(module, demand)?
            } else {
                rows.crate_owner_import_inventory(
                    module,
                    demand,
                    module.selected_blob,
                    owner_scope.get(),
                )?
            };
            facts.completion = facts.completion.combine(&inventory.completion);
            binding_targets = inventory.targets;
        }
        Ok(binding_targets)
    }
    fn module_starts(
        &self,
        module: &Module,
        facts: &PlacementFacts<Self::Target>,
    ) -> Vec<PlacementStart<Self::Member>> {
        if facts.targets.is_empty()
            && self.source.prefix.is_none()
            && !(self.source.is_import && self.source.route.is_empty())
            && self.lexical.node_is_scope_head_in(
                self.scope_ordinals,
                self.source.scope,
                module.fragment,
                module.scope,
            )
        {
            vec![PlacementStart::Route {
                rank: None,
                scope: None,
                cursor: WalkCursor::container(facts.tag, module.topology, module.path.clone(), 0),
                anchor: self.source.anchor,
            }]
        } else {
            Vec::new()
        }
    }
    fn lexical_parent(
        &self,
        module: &Module,
        scope: ResolutionScopeId,
    ) -> Result<Option<ResolutionScopeId>> {
        self.rows.ready.lexical_source().lookup_scope_parent(
            module.fragment,
            scope,
            self.rows.cancellation,
        )
    }
    fn lexical_tier(
        &self,
        module: &Module,
        scope: ResolutionScopeId,
        depth: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Self::LexicalTiers>> {
        use super::super::demand_closure::RouteEdgeTier;
        let conn = self.rows.ready.inventory.connection();
        let rows = RustCrateRows {
            ready: self.rows.ready,
        };
        let name = lookup.spelling();
        let module_level = scope == module.scope;
        let inventory = if module_level {
            rows.crate_binding_inventory(module, module.topology, &module.path, "type", name)?
        } else {
            rows.crate_owner_binding_inventory(
                module.topology,
                &module.path,
                module.selected_blob,
                scope.get(),
                "type",
                name,
            )?
        };
        let mut tier = RouteEdgeTier {
            coverage: inventory.completion.clone(),
            blocks_fallback: inventory.targets.is_some()
                || inventory.completion != ResolutionCompletion::Complete,
            ..RouteEdgeTier::default()
        };
        let has_exact_set = inventory.targets.is_some();
        let bindings = if let Some(targets) = inventory.targets {
            targets
        } else {
            conn.prepare_cached(sql::IMPORT_MODULE_PREFIX_STARTS)?
                .query_map(
                    params![
                        module.topology,
                        module.path,
                        module.blob,
                        scope.get(),
                        name,
                        "type",
                        module.selected_blob
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let has_named_binding = !bindings.is_empty();
        tier.blocks_fallback |= has_named_binding;
        for (topology, path, target_name) in bindings {
            tier.edges.extend(
                sql::published_module_starts(
                    conn,
                    topology,
                    &path,
                    &target_name,
                    module.topology,
                    &module.path,
                )?
                .into_iter()
                .map(|(unit, container)| RouteLocation::Container { unit, container }),
            );
        }
        let head = (module_level && !has_exact_set && !has_named_binding).then(|| {
            (
                RouteLocation::Container {
                    unit: module.topology,
                    container: module.path.clone(),
                },
                lookup.clone(),
            )
        });
        Ok(Read::ready(std::iter::once(
            super::super::demand_closure::LexicalStartTier {
                ranked: super::super::demand_closure::RankedLexicalTier {
                    rank: (depth, 0),
                    tier,
                    providers: Vec::new(),
                },
                head,
            },
        )))
    }
    fn lexical_selection(
        &self,
        module: &Module,
        facts: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection>> {
        if !(facts.targets.is_empty()
            && self.source.prefix.is_none()
            && self.source.anchor == ResolutionRootImportAnchor::Lexical)
        {
            return Ok(None);
        }
        let Some(root) = self.source.route.first() else {
            return Ok(None);
        };
        let start_scope = self
            .scope_ordinals
            .get(&self.source.scope)
            .copied()
            .flatten()
            .filter(|(fragment, _)| *fragment == module.fragment)
            .map_or(module.scope, |(_, owner_scope)| owner_scope);
        let selected = self
            .rows
            .route_starts(module, start_scope, root.spelling())?;
        Ok(Some(selected))
    }
    fn lexical_starts(
        &self,
        selected: StartSelection,
        facts: &PlacementFacts<Self::Target>,
    ) -> Vec<PlacementStart<Self::Member>> {
        selected
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                rank: start.rank,
                scope: start.scope,
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: 1,
                    start_step: 1,
                    namespace: ResolutionNamespace::Type,
                },
                anchor: ResolutionRootImportAnchor::Lexical,
            })
            .collect()
    }
    fn observe_targets(
        &mut self,
        module: &Module,
        facts: &PlacementFacts<Self::Target>,
    ) -> Result<()> {
        let conn = self.rows.ready.inventory.connection();
        let rows = RustCrateRows {
            ready: self.rows.ready,
        };
        let demand = &self.source.demand;
        let route = &self.source.route;
        // A single-segment `use` names the path root alone. Nothing
        // in this workspace can bind it unless the root names a crate
        // the Cargo graph resolved, so the extern prelude is the whole
        // answer: a hit means the root is a workspace crate, and that
        // this workspace publishes no export for a crate root is its
        // own business, not a boundary. One placement that names the
        // crate settles it for the half, because the half asks about
        // the workspace and a placement answers for one topology.
        if route.is_empty()
            && let Some(name) = self.import_root_name.as_deref()
        {
            self.root_names_a_workspace_crate |= conn
                .prepare_cached(sql::DEPENDENCY.as_str())?
                .exists(params![
                    module.topology,
                    name,
                    RUST_UNIT_SUMMARY_DERIVATION_VERSION
                ])?;
        }
        // A qualified reference can stop at a module import whose
        // source is unindexed. Keep that original binding identity,
        // just as the ordinary export lookup does, rather than naming
        // the reference token as a fresh external type or subject.
        if !self.source.is_import
            && self.source.prefix.is_none()
            && facts.targets.is_empty()
            && let Some(root) = route.first()
        {
            self.external_root_bindings
                .extend(rows.crate_external_bindings(
                    module,
                    module.topology,
                    &module.path,
                    demand.namespace(),
                    root.spelling(),
                )?);
        }
        Ok(())
    }
    fn select_targets(&self, targets: &mut Vec<Self::Target>) -> Result<()> {
        if sql::is_module_anchor(self.source.demand.spelling()) {
            *targets = RustCrateRows {
                ready: self.rows.ready,
            }
            .anchor_declaration_targets(std::mem::take(targets))?;
        }
        Ok(())
    }
    fn exports(
        &self,
        module: &Module,
        target: Self::Target,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        self.rows
            .exports(module, target, &self.source.demand, completion)
    }
    fn empty_target(&self, module: &Module, target: &Self::Target) -> Result<ResolutionCompletion> {
        let rows = RustCrateRows {
            ready: self.rows.ready,
        };
        let demand = &self.source.demand;
        let mut inventory = rows.crate_inventory_completion(
            module,
            target.0,
            &target.1,
            sql::namespace(demand.namespace()),
            &target.2,
        )?;
        let bindings = rows.crate_external_bindings(
            module,
            target.0,
            &target.1,
            demand.namespace(),
            &target.2,
        )?;
        if !bindings.is_empty() {
            inventory = ResolutionCompletion::incomplete(bindings.into_iter().map(|semantic| {
                ResolutionIncompleteReason::OpenBoundary {
                    semantic,
                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                }
            }));
        }
        Ok(inventory)
    }
    fn empty_placement(
        &mut self,
        facts: &PlacementFacts<Self::Target>,
        observation: &mut HalfObservation,
    ) -> Result<()> {
        if let Some(resolved) = &self.resolved {
            let generated_surface =
                super::super::rust_crate_context::generated_item_surface_boundary(
                    self.rows.ready,
                    &resolved.targets,
                )?;
            if generated_surface != ResolutionCompletion::Complete {
                self.known_prefix = true;
                observation.completion = observation.completion.combine(&generated_surface);
            }
        }
        observation.completion = observation.completion.combine(&facts.completion);
        Ok(())
    }
    fn boundary(&mut self, observation: &HalfObservation) -> Result<Option<HalfBoundary>> {
        let conn = self.rows.ready.inventory.connection();
        let rows = RustCrateRows {
            ready: self.rows.ready,
        };
        let demand = &self.source.demand;
        let route = &self.source.route;
        let mut pending_completion = observation.completion.clone();
        let mut associations = Vec::new();
        // A path whose first segment names no module this workspace
        // compiles has left the workspace, and that is a boundary, not
        // a decided negative. Which segment carries the question
        // depends on the half's shape: an anchored or multi-segment
        // route carries it in `route`, while a bare two-segment path
        // carries it as the prefix reference, whose lexical lookup and
        // whose Cargo dependency lookup both came back empty. A
        // single-segment `use` carries it as the import's own root
        // name.
        //
        // Both sides used to be left out. The prefix shape claimed
        // nothing at all, so `ext_crate::Widget` answered a complete
        // absence, and a reference took `UnsupportedSemantic`, which
        // names no boundary and can only ever read as "incomplete for
        // an unstated reason". The import arm has claimed the boundary
        // since lane T added the row; an import and a reference are
        // asking the same question about the same root.
        //
        // The question is about the route head and the workspace, so
        // the half owns it and no single module placement can answer
        // it. A file compiled into more than one topology asks it once
        // per placement, and only the placement whose topology
        // declares the dependency binds the root; claiming the
        // boundary per placement said a workspace crate had left the
        // workspace.
        let root_name = match route.first() {
            Some(segment) => Some(segment.spelling()),
            None => self.import_root_name.as_deref(),
        };
        // `Self` or a type parameter heading a path to one of its
        // members (`Self::check`, `T::one`) is a type and not a
        // module: the typed member route answers the member through
        // the enclosing impl or trait, or through the parameter's
        // bounds. The crate route has nothing to continue through,
        // and neither a boundary nor a negative to claim: `Self` binds
        // no name, so its lookup comes back empty, but that is not a
        // root that left the workspace. Claiming either made the
        // answer incomplete, or an import boundary, even where the
        // typed route found the member.
        let type_prefix = !self.known_prefix
            && self.prefix_kind == super::super::rust_crate_context::RoutePrefixKind::MemberType;
        if type_prefix {
            pending_completion = pending_completion.combine(
                &self
                    .resolved
                    .as_ref()
                    .expect("a prefix has a resolution")
                    .completion,
            );
        }
        // A half whose fragment places no module was never asked,
        // and an unasked question has no boundary to claim.
        // A prefix an import anchored in this crate binds names a
        // module of this crate, so a route that found nothing did not
        // leave the workspace: no boundary. It is not a decided
        // absence either, because the crate rows cannot yet prove
        // every such walk closed (items declared through macros or
        // re-exported from other crates), so it stays the dead end.
        let bound_in_the_crate = match (self.source.prefix, self.resolved.as_ref()) {
            (Some(prefix), Some(resolved)) if !self.known_prefix => {
                super::super::rust_crate_context::prefix_bound_in_the_crate(
                    self.rows.ready,
                    prefix,
                    resolved,
                    self.rows.cancellation,
                )?
            }
            _ => false,
        };
        let external_root = !observation.answered_placements.is_empty()
            && !observation.route_reached_a_target
            && !self.root_names_a_workspace_crate
            && match self.source.prefix {
                None => root_name.is_some_and(|name| !sql::is_module_anchor(name)),
                Some(_) => {
                    !self.known_prefix
                        && !bound_in_the_crate
                        && !type_prefix
                        && !self.local_type_prefix_is_decided
                        && self.resolved.as_ref().is_some_and(|resolved| {
                            super::super::rust_crate_context::prefix_left_the_indexed_workspace(
                                self.rows.ready,
                                resolved,
                            )
                        })
                }
            };
        if external_root {
            if self.source.is_import && !self.external_type_import_scopes.is_empty() {
                let mut import_paths = Vec::new();
                for &(blob, scope) in &self.external_type_import_scopes {
                    let Some(paths) = rows.external_type_import_paths_for_binding(
                        blob,
                        scope,
                        demand.spelling(),
                        self.rows.cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    import_paths.extend(paths);
                }
                associations.push(
                    super::super::demand_closure::ContextAssociation::ExternalTypeImport {
                        boundary: self.source.token,
                        paths: import_paths,
                    },
                );
            }
            if self.external_root_bindings.is_empty() {
                self.external_root_bindings.push(self.source.token);
            }
            pending_completion = pending_completion.combine(&ResolutionCompletion::incomplete(
                self.external_root_bindings.iter().copied().map(|semantic| {
                    ResolutionIncompleteReason::OpenBoundary {
                        semantic,
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    }
                }),
            ));
        }
        // An unqualified name no scope binds falls through to the
        // crate's implicit prelude (the producer's route-less root
        // reference). When that prelude supplies the name, it is an
        // item of the unindexed std or core crate: an open boundary
        // naming the prelude, never a proved absence.
        if !self.source.is_import
            && self.source.prefix.is_none()
            && route.is_empty()
            && !external_root
        {
            for &topology in &self.placed_topologies {
                if let Some(boundary) = sql::prelude_boundary(
                    conn,
                    &self.rows.ready.context_identities,
                    topology,
                    demand,
                )? {
                    associations.push(
                        super::super::demand_closure::ContextAssociation::PreludeReference {
                            reference: self.source.token,
                            boundary,
                        },
                    );
                    pending_completion = pending_completion.combine(
                                &ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::OpenBoundary {
                                        semantic: boundary,
                                        status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                                    },
                                ]),
                            );
                    break;
                }
            }
        }
        // A boundary is the answer to this question. When the claim
        // above named `ExternalDeclaredUnindexed` for this token, the
        // route has already said the name left the workspace, and the
        // prefix is the segment that took it there. Restating both as
        // coarse reasons asks the same question twice and defeats the
        // all-boundary predicate in `rust/native_points.rs`, which is
        // why `ext_crate::Widget` answered `incomplete` instead of
        // `unresolvable_import_boundary`. The coarse reason is
        // discharged here, beside the claim, so no consumer has to
        // match reason kinds against semantics.
        let claimed_boundary =
            pending_completion.contains_reason(ResolutionIncompleteReason::OpenBoundary {
                semantic: self.source.token,
                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
            });
        if let Some(prefix) = self.source.prefix
            && !self.known_prefix
            && !claimed_boundary
            && !type_prefix
        {
            let rel_path = self
                .rows
                .mount_table()
                .mount_for_fragment(self.source.identity.fragment())?
                .map(|mount| mount.persisted_relative_path().to_owned());
            let prefix_class = super::super::rust_crate_context::classify_route_prefix(
                self.rows.ready,
                rel_path.as_deref(),
                self.prefix_spelling.as_deref(),
                self.resolved.as_ref().expect("a prefix has a resolution"),
                prefix.ordinal(),
                route.is_empty(),
                self.rows.cancellation,
            )?;
            if prefix_class != super::super::rust_crate_context::RoutePrefixClass::OpenInventory {
                pending_completion =
                    pending_completion.combine(&super::super::rust_crate_context::route_dead_end(
                        &self.rows.ready.context_identities,
                        super::super::rust_crate_context::RouteDeadEnd::UnplacedRoutePrefix,
                        rel_path.as_deref(),
                        self.prefix_spelling.as_deref(),
                        Some(prefix_class),
                        route,
                        demand,
                    ));
            }
        }
        Ok(Some(HalfBoundary {
            completion: pending_completion,
            associations,
        }))
    }
}

pub(super) const PREFIX_MODULES: &str =
    "WITH RECURSIVE graph(topology_id, summary_id, unit_key) AS (
 SELECT topology_id, summary_id, unit_key
 FROM selected_rust_unit_summaries WHERE topology_id=?3
 UNION SELECT target.topology_id, target.summary_id, target.unit_key FROM graph
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=graph.summary_id
 CROSS JOIN selected_rust_unit_summaries AS target
  ON target.unit_key=dependency.dependency_unit_key
) SELECT placement.topology_id, modules.container_path, authority.blob_id, authority.source_site,
 mount.persisted_relative_path
 FROM selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id=authority.blob_id AND mapping.declaration_id=authority.declaration
 CROSS JOIN code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 CROSS JOIN selected_rust_unit_summaries AS owner ON owner.topology_id=placement.topology_id
 LEFT JOIN main.resolution_unit_summary_containers AS modules
  ON modules.summary_id=owner.summary_id
  AND modules.container_path=placement.container_path || '::' || unit.identifier
 WHERE mount.mount_ordinal=?1 AND placement.topology_id IN (SELECT topology_id FROM graph)";

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        (
            "rust_point_demand_modules",
            super::super::rust_crate_rows::MODULES_FOR_BLOB,
            3,
        ),
        (
            "rust_point_demand_reverse_export_names",
            REVERSE_EXPORTED_NAMES,
            4,
        ),
        ("rust_point_demand_prefix_modules", PREFIX_MODULES, 3),
    ]
}
