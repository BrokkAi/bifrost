//! One endpoint's finite crate-row plan. Nothing here is retained by a selection.
use super::super::rust_crate_context::{self as sql, Module};
use super::super::rust_crate_rows::{RustCrateDeclaration, RustCrateExport, RustCrateRows};
use super::super::rust_prefix::{RustQualifiedPrefix, resolve_rust_type_prefix};
use super::super::*;
use crate::analyzer::resolution::{
    BatchCandidateRequest, EndpointSignature, FactResolutionAnswer, StackPattern, mounted_site_node,
};
use rusqlite::{OptionalExtension, params};

pub(crate) struct RowRootPlan {
    pub(crate) halves: Vec<SelectedRootPathHalf>,
    pub(crate) prefixes: Vec<RustQualifiedPrefix>,
    pub(crate) completion: ResolutionCompletion,
}

pub(super) struct EndpointRows<'a, 'store, 'input> {
    pub(super) ready: &'a ReadySelectedResolution<'store, 'input>,
    pub(super) base: &'a dyn BatchResolutionFragmentSource,
    pub(super) cancellation: &'a CancellationToken,
    pub(super) topologies: &'a [i64],
}

impl<'a, 'store> EndpointRows<'a, 'store, '_> {
    fn mount_table(&self) -> SelectedMountTable<'a, 'store> {
        SelectedMountTable::new(&self.ready.inventory)
    }

    /// The canonical lookup recipe one sealed demand names, or `None` when
    /// reading it was cancelled.
    ///
    /// A cancelled read used to be reported as a store error, and the point
    /// entry turns a store error into an unavailable answer rather than a
    /// cancelled one. Nothing reached it until the cancellation checks a
    /// per-mount identity-catalog walk used to consume went away.
    fn recipe(
        &self,
        fragment: BindingFragmentId,
        semantic: SemanticId,
    ) -> Result<Option<ResolutionLookupSemanticRecipe>> {
        let source = self.ready.lexical_source();
        let request = SelectedLookupRecipeRequest { fragment, semantic };
        let SelectedLookupRecipeReadOutcome::Ready(rows) =
            source.lookup_semantic_recipes(&[request], self.cancellation, None)?
        else {
            return Ok(None);
        };
        rows.into_vec()
            .pop()
            .flatten()
            .map(Some)
            .ok_or_else(|| StoreError::corrupt("sealed demand has no lookup recipe"))
    }

    /// The module placements a root half of `fragment` is asked in, and the
    /// incompleteness of a file the request's crates do not compile.
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
            self.cancellation,
        )?;
        // One row per Cargo target that compiles this file. A request made on
        // behalf of one target follows the root anchor in that target only:
        // `src/api.rs` compiled by both a library and a binary has two rows,
        // and following both made `crate::error` name the library's
        // `mod error;` and the binary's at once, which no owner can then
        // prove. The statement is unchanged, so the read costs what it did;
        // the request's own topologies are a handful of integers it already
        // holds, and a request that names no crate keeps every row.
        let requested = self.topologies;
        let (asked, outside): (Vec<_>, Vec<_>) = modules
            .into_iter()
            .partition(|module| requested.is_empty() || requested.contains(&module.topology));
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
    ) -> Result<
        Option<(
            Vec<(
                SelectedRootPathHalf,
                ResolutionLookupSemanticRecipe,
                ResolutionCompletion,
            )>,
            ResolutionCompletion,
        )>,
    > {
        let rows = RustCrateRows { ready: self.ready };
        let mut bridges = Vec::new();
        let mut path_completions = Vec::new();
        let mut exports = rows.crate_exports(
            module,
            target.0,
            &target.1,
            sql::namespace(demand.namespace()),
            &target.2,
        )?;
        exports.sort_unstable();
        exports.dedup();
        let mut cancelled = false;
        let mut definitions = Vec::new();
        let mut unstaged = ResolutionCompletion::Complete;
        for RustCrateExport {
            blob,
            declaration,
            mount: ordinal,
            ..
        } in exports
        {
            let mount = self.mount_table().mount_by_ordinal(ordinal)?;
            match declaration {
                // Crate rows name ordinary declaration sites; the selected
                // reader validates their catalog authority before reading
                // candidate paths. This source site belongs to the actual
                // selected content.
                RustCrateDeclaration::Site(site) => {
                    let semantic = crate::analyzer::resolution::mounted_site_semantic(
                        mount.fragment(),
                        ResolutionSiteId::new(site),
                    );
                    let Some(node) = self
                        .base
                        .lookup_definition_node(semantic, self.cancellation)?
                    else {
                        // The row proves the name is declared here; the file's
                        // lowering withheld the declaration, so this is not an
                        // absence.
                        unstaged = unstaged.combine(
                            &super::super::rust_crate_context::unlowered_export_declaration(
                                &self.ready.context_identities,
                                mount.persisted_relative_path(),
                                site,
                            ),
                        );
                        continue;
                    };
                    assert_eq!(
                        node,
                        mounted_site_node(mount.fragment(), ResolutionSiteId::new(site))
                    );
                    definitions.push(node);
                }
                // An item the crate declared for a decided passthrough
                // invocation is defined by the invoking file's capsule, which
                // lowered the item at the byte range where replay declared
                // its name. The request staged that capsule when a name its
                // files spell is the item's. One that did not -- a re-export
                // chain renamed the item on the way -- finds no staged
                // definition, and says so: the module's export inventory is
                // closed, so an empty answer here would read as an absence. A
                // module item never has a capsule definition (see
                // `MACRO_ITEM_NAME_RANGE`); the crate route steps through it
                // by `MACRO_ITEM_MODULE`, and a reference to the module
                // itself answers incomplete the same way.
                RustCrateDeclaration::MacroItem(declaration) => {
                    let (start, end, module) = self
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(sql::MACRO_ITEM_NAME_RANGE)?
                        .query_row(params![blob, declaration], |row| {
                            Ok((
                                row.get::<_, usize>(0)?,
                                row.get::<_, usize>(1)?,
                                row.get::<_, bool>(2)?,
                            ))
                        })?;
                    let Some(staged) = self.ready.lexical_source().stage_definitions_at_range(
                        ordinal,
                        start,
                        end,
                        self.cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    if staged.is_empty() {
                        unstaged = unstaged.combine(&sql::unstaged_macro_item(
                            &self.ready.context_identities,
                            blob,
                            declaration,
                            module,
                        ));
                    }
                    definitions.extend(staged.into_iter().map(|(_, node)| node));
                }
            }
        }
        for node in definitions {
            let endpoint =
                EndpointSignature::new(node, StackPattern::closed([]), StackPattern::closed([]));
            let anchors = self.ready.lexical_source();
            self.base.visit_reverse_candidate_match_pages(
                &[BatchCandidateRequest::new(0, endpoint)],
                self.cancellation,
                &mut |page| {
                    let ids = page.iter().map(|row| row.candidate()).collect::<Vec<_>>();
                    for (id, path) in self.base.hydrate_candidate_paths(&ids, self.cancellation)? {
                        let Some(
                            export_half @ SelectedRootPathHalf::Export {
                                demand: export_demand,
                                ..
                            },
                        ) = classify_selected_root_path_half(
                            &anchors,
                            id,
                            &path,
                            self.cancellation,
                        )?
                        else {
                            continue;
                        };
                        let Some(target_demand) = self.recipe(id.fragment(), export_demand)? else {
                            cancelled = true;
                            return Ok(false);
                        };
                        if target_demand.namespace() != demand.namespace() {
                            continue;
                        }
                        path_completions.push(path.completion().clone());
                        bridges.push((export_half, target_demand, completion.clone()));
                    }
                    Ok(!self.cancellation.is_cancelled())
                },
            )?;
            if cancelled {
                return Ok(None);
            }
        }
        // Close both export and path evidence in one query-owned SQL batch.
        // Keep the caller's completion separate, as the former closure did.
        let mut completions = Vec::with_capacity(bridges.len() * 2);
        for ((half, _, _), path) in bridges.iter().zip(path_completions) {
            let SelectedRootPathHalf::Export {
                incomplete_reasons, ..
            } = half
            else {
                unreachable!("export query collects export halves");
            };
            completions.push(if incomplete_reasons.is_empty() {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::incomplete(incomplete_reasons.iter().copied())
            });
            completions.push(path);
        }
        let Some(closed) = self
            .ready
            .lexical_source()
            .close_completions(&completions, self.cancellation)?
        else {
            return Ok(None);
        };
        let mut closed = closed.into_iter();
        for (half, _, evidence) in &mut bridges {
            let SelectedRootPathHalf::Export {
                incomplete_reasons, ..
            } = half
            else {
                unreachable!("export query collects export halves");
            };
            *incomplete_reasons = match closed.next().expect("export completion") {
                ResolutionCompletion::Complete => Box::new([]),
                ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect(),
            };
            *evidence = evidence
                .combine(&closed.next().expect("path completion"))
                .combine(&unstaged);
        }
        assert!(closed.next().is_none());
        Ok(Some((bridges, unstaged)))
    }
}

/// Every crate-row name that reaches one exported declaration.
///
/// The seed is the declaration's own source site in one export namespace; the
/// caller certifies its namespace from canonical root export halves. The
/// selected declaration supplies its current name and module authority; its
/// selected mount supplies placement. The recursion then follows
/// re-export routes, glob re-exports and imports over the crate rows.
pub(super) const REVERSE_EXPORTED_NAMES: &str = "WITH RECURSIVE names(topology_id, module_path, namespace, name) AS (
 SELECT placement.topology_id,
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
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=placement.topology_id
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
  AND cr_cfg(properties.cfg_condition,json(owner.cfg_atoms))=1
 UNION
 SELECT route.topology_id, route.module_path, names.namespace, route.bound_name
 FROM names
 CROSS JOIN selected_rust_crates AS target ON target.topology_id=names.topology_id
 CROSS JOIN rust_crate_reexport_routes AS route ON route.target_crate_key=target.crate_key
 AND route.target_module_path=names.module_path AND route.target_name=names.name
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=route.topology_id
 UNION
 SELECT route.topology_id, route.module_path, names.namespace, names.name
 FROM names
 CROSS JOIN selected_rust_crates AS target ON target.topology_id=names.topology_id
 CROSS JOIN rust_crate_glob_reexport_routes AS route ON route.target_crate_key=target.crate_key
 AND route.target_module_path=names.module_path
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=route.topology_id
 UNION
 SELECT imports.topology_id, imports.module_path, names.namespace, imports.bound_name
 FROM names
 CROSS JOIN selected_rust_crates AS target ON target.topology_id=names.topology_id
 CROSS JOIN rust_crate_imports AS imports ON imports.target_crate_key=target.crate_key
 AND imports.target_module_path=names.module_path AND imports.target_name=names.name AND imports.namespace=names.namespace
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=imports.topology_id
) SELECT DISTINCT namespace, name FROM names";

impl EndpointRows<'_, '_, '_> {
    /// Close one endpoint plan's root bridges, or `None` when the read was
    /// cancelled part way.
    pub(super) fn close(
        &self,
        plan: &RowRootPlan,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let conn = self.ready.inventory.connection();
        let lexical = self.ready.lexical_source();
        let rows = RustCrateRows { ready: self.ready };
        let Some(scope_ordinals) = lexical.node_scope_ordinals(
            plan.halves.iter().filter_map(|half| match half {
                SelectedRootPathHalf::Import {
                    source_scope_head, ..
                }
                | SelectedRootPathHalf::Reference {
                    source_scope_head, ..
                } => Some(*source_scope_head),
                SelectedRootPathHalf::Export { .. } => None,
            }),
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut descriptors = Vec::new();
        for half in &plan.halves {
            let (identity, scope, token, demand_id, route_ids, anchor, anchor_semantic, prefix) =
                match half {
                    SelectedRootPathHalf::Import {
                        identity,
                        source_scope_head,
                        token,
                        demand,
                        route,
                        anchor,
                        anchor_semantic,
                    } => (
                        *identity,
                        *source_scope_head,
                        *token,
                        *demand,
                        route,
                        *anchor,
                        *anchor_semantic,
                        None,
                    ),
                    SelectedRootPathHalf::Reference {
                        identity,
                        source_scope_head,
                        token,
                        demand,
                        route,
                        anchor,
                        anchor_semantic,
                        prefix_reference,
                        ..
                    } => (
                        *identity,
                        *source_scope_head,
                        *token,
                        *demand,
                        route,
                        *anchor,
                        *anchor_semantic,
                        *prefix_reference,
                    ),
                    _ => unreachable!("one source endpoint plan contains only source halves"),
                };
            let Some(demand) = self.recipe(identity.fragment(), demand_id)? else {
                return Ok(None);
            };
            let Some(route) = route_ids
                .iter()
                .map(|id| self.recipe(identity.fragment(), *id))
                .collect::<Result<Option<Vec<_>>>>()?
            else {
                return Ok(None);
            };
            let is_import = matches!(half, SelectedRootPathHalf::Import { .. });
            let resolved = prefix.map(|prefix| {
                let (_, answer) = inputs
                    .iter()
                    .find(|(reference, _)| *reference == prefix)
                    .expect("scheduler supplies every prefix");
                resolve_rust_type_prefix(answer)
            });
            let local_type_prefix_is_decided = match &resolved {
                Some(resolved) => {
                    super::super::rust_crate_context::block_local_type_prefix_binding_is_decided(
                        self.ready,
                        &resolved.targets,
                        &resolved.completion,
                    )?
                }
                None => false,
            };
            // Placements are alternative justifications for one canonical
            // export. Close their evidence before issuing its immutable cell.
            let mut authorities: HashMap<
                _,
                (
                    SelectedRootPathHalf,
                    ResolutionLookupSemanticRecipe,
                    ResolutionCompletion,
                ),
            > = HashMap::default();
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
            let mut import_root_name = None;
            // Both are the half's, not one module placement's. A file this
            // fragment's modules place more than once asks the route-head
            // question once per placement, and only the placement whose
            // topology declares the dependency can bind the root; claiming the
            // boundary per placement said a workspace crate left the
            // workspace. The graph route's copy of this guard says the same
            // thing (`rust_crate_context.rs`), and the two must not drift.
            let mut route_reached_a_target = false;
            let mut root_names_a_workspace_crate = false;
            let mut external_root_bindings = Vec::new();
            let mut external_type_import_scopes = Vec::new();
            let mut answered_placements = 0_usize;
            let mut member_bridges = Vec::new();
            let (modules, outside_request) = self.modules(identity.fragment())?;
            pending_completion = pending_completion.combine(&outside_request);
            let placed_topologies = modules
                .iter()
                .map(|module| module.topology)
                .collect::<Vec<_>>();
            for module in modules {
                if !is_import
                    && !lexical.node_is_scope_head_in(
                        &scope_ordinals,
                        scope,
                        module.fragment,
                        module.scope,
                    )
                {
                    continue;
                }
                let mut targets = Vec::new();
                let mut completion = module.overlay_completion.combine(&plan.completion);
                if let Some(resolved) = &resolved {
                    if !local_type_prefix_is_decided {
                        completion = completion.combine(&resolved.completion);
                    }
                    let mut prefix_starts = Vec::new();
                    for target in &resolved.targets {
                        if self
                            .base
                            .lookup_definition_node(*target, self.cancellation)?
                            .is_none()
                        {
                            continue;
                        }
                        let Some(
                            crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(
                                provenance,
                            ),
                        ) = lexical.semantic_provenance(*target, self.cancellation)?
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
                    known_prefix |= !prefix_starts.is_empty();
                    if prefix_starts
                        .iter()
                        .any(|(_, path, _, _, _)| path.is_some())
                        && prefix_starts
                            .iter()
                            .any(|(_, path, _, _, _)| path.is_none())
                    {
                        let rel_path = self
                            .mount_table()
                            .mount_for_fragment(identity.fragment())?
                            .map(|mount| mount.persisted_relative_path().to_owned());
                        let prefix_spelling = self
                            .ready
                            .rust_prefix_spellings(
                                &self.ready.lexical_source(),
                                &[prefix.expect("a mixed prefix exists")],
                                self.cancellation,
                            )?
                            .into_values()
                            .next();
                        completion =
                            completion.combine(&super::super::rust_crate_context::route_dead_end(
                                &self.ready.context_identities,
                                super::super::rust_crate_context::RouteDeadEnd::MixedRoutePrefix,
                                rel_path.as_deref(),
                                prefix_spelling.as_deref(),
                                None,
                                &route,
                                &demand,
                            ));
                    }
                    for (id, path, subject_blob, subject_site, subject_path) in prefix_starts {
                        let Some(path) = path else {
                            // The prefix named a declaration that is not a
                            // module, so the module walk has no continuation.
                            // With nothing left of the route the demand is a
                            // member of that declaration, and a trait it
                            // implements can declare it. The bridge's start
                            // stack is the reference's, so an empty route is
                            // the condition and not a convenience: a half that
                            // still carries segments spells a different stack.
                            if route.is_empty() {
                                member_bridges.extend(rows.crate_trait_member_bridges(
                                    &self.mount_table(),
                                    &module,
                                    identity.fragment(),
                                    token,
                                    anchor,
                                    anchor_semantic,
                                    prefix.expect("a resolved prefix names its reference"),
                                    &demand,
                                    subject_blob,
                                    subject_site,
                                    &subject_path,
                                    &completion,
                                    self.cancellation,
                                )?);
                            }
                            continue;
                        };
                        for (id, path) in rows.crate_route(
                            &module,
                            id,
                            path,
                            &route[route.len().min(1)..],
                            ResolutionRootImportAnchor::Lexical,
                            &mut completion,
                            self.cancellation,
                        )? {
                            targets.push((id, path, demand.spelling().to_owned()));
                        }
                    }
                    if (resolved.targets.is_empty()
                        && resolved.completion == ResolutionCompletion::Complete)
                        || anchor == ResolutionRootImportAnchor::Absolute
                    {
                        let mut starts = Vec::new();
                        if anchor == ResolutionRootImportAnchor::Absolute {
                            starts.push((module.topology, "crate".to_owned()));
                        } else {
                            let prefix = prefix.expect("resolved prefix");
                            let names = self.ready.rust_prefix_spellings(
                                &self.ready.lexical_source(),
                                &[prefix],
                                self.cancellation,
                            )?;
                            if let Some(name) = names.get(&prefix) {
                                starts.extend(sql::crate_root_prefix_starts(conn, &module, name)?);
                                // A module an item macro declares in this module
                                // has no lexical binder, so the prefix found
                                // nothing lexically; the crate row places it.
                                for row in conn.prepare_cached(sql::NAMED_MACRO_MODULE)?.query_map(
                                    params![module.topology, module.path, name],
                                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                                )? {
                                    starts.push(row?);
                                }
                            }
                        }
                        known_prefix |= !starts.is_empty();
                        for (id, path) in starts {
                            for (id, path) in rows.crate_route(
                                &module,
                                id,
                                path,
                                &route,
                                anchor,
                                &mut completion,
                                self.cancellation,
                            )? {
                                targets.push((id, path, demand.spelling().to_owned()));
                            }
                        }
                    }
                } else if is_import {
                    let mut matched_scope = false;
                    for raw in (RustCrateRows { ready: self.ready })
                        .module_import_scopes(module.blob, module.scope.get())?
                    {
                        if self.cancellation.is_cancelled() {
                            return Ok(None);
                        }
                        if !lexical.node_is_scope_head_in(
                            &scope_ordinals,
                            scope,
                            module.fragment,
                            ResolutionScopeId::new(raw),
                        ) {
                            continue;
                        }
                        matched_scope = true;
                        if demand.namespace() == ResolutionNamespace::Type {
                            external_type_import_scopes.push((module.blob, raw));
                        }
                        if route.is_empty() && import_root_name.is_none() {
                            import_root_name = conn
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
                            let id = conn
                                .prepare_cached(sql::CRATE)?
                                .query_row([key], |row| row.get(0))?;
                            targets.push((id, path, name));
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
                            let id = conn
                                .prepare_cached(sql::CRATE)?
                                .query_row([key], |row| row.get(0))?;
                            targets.push((id, path, demand.spelling().to_owned()));
                        }
                    }
                    if !matched_scope && completion == ResolutionCompletion::Complete {
                        continue;
                    }
                }
                // An import with no route segments binds the path root itself,
                // so the module it is written in is not a place to look:
                // `use serde as s;` does not bind whatever `serde` names
                // inside the current module. Walking an empty route from that
                // module would answer it with the module, which is why the
                // walk below is not this half's continuation. The extern
                // prelude decides that root.
                if targets.is_empty()
                    && prefix.is_none()
                    && !(is_import && route.is_empty())
                    && lexical.node_is_scope_head_in(
                        &scope_ordinals,
                        scope,
                        module.fragment,
                        module.scope,
                    )
                {
                    for (id, path) in rows.crate_route(
                        &module,
                        module.topology,
                        module.path.clone(),
                        &route,
                        anchor,
                        &mut completion,
                        self.cancellation,
                    )? {
                        targets.push((id, path, demand.spelling().to_owned()));
                    }
                }
                // A single-segment `use` names the path root alone. Nothing
                // in this workspace can bind it unless the root names a crate
                // the Cargo graph resolved, so the extern prelude is the whole
                // answer: a hit means the root is a workspace crate, and that
                // this workspace publishes no export for a crate root is its
                // own business, not a boundary. One placement that names the
                // crate settles it for the half, because the half asks about
                // the workspace and a placement answers for one topology.
                if route.is_empty()
                    && let Some(name) = import_root_name.as_deref()
                {
                    root_names_a_workspace_crate |= conn
                        .prepare_cached(sql::DEPENDENCY)?
                        .exists(params![module.topology, name])?;
                }
                // A qualified reference can stop at a module import whose
                // source is unindexed. Keep that original binding identity,
                // just as the ordinary export lookup does, rather than naming
                // the reference token as a fresh external type or subject.
                if !is_import
                    && prefix.is_none()
                    && targets.is_empty()
                    && let Some(root) = route.first()
                {
                    external_root_bindings.extend(rows.crate_external_bindings(
                        &module,
                        module.topology,
                        &module.path,
                        demand.namespace(),
                        root.spelling(),
                    )?);
                }
                // An anchor names the module its own route step reached, so
                // its target is that module's declaration rather than an
                // export inside it.
                if sql::is_module_anchor(demand.spelling()) {
                    targets = rows.anchor_declaration_targets(targets)?;
                }
                route_reached_a_target |= !targets.is_empty();
                let before = authorities.len();
                for target in targets {
                    let Some((exports, unstaged)) =
                        self.exports(&module, target.clone(), &demand, &completion)?
                    else {
                        return Ok(None);
                    };
                    if exports.is_empty() {
                        // With every module the walk reached closed, the
                        // empty answer is a proved absence, which the route
                        // reads as the external boundary when nothing binds
                        // the name. One open module withholds that proof. The
                        // walk can still find the name as an import whose path
                        // leaves the workspace, such as a glob reaching
                        // `pub use std::sync::Arc;`: that is the answer, the
                        // boundary, and a found name is not reopened by
                        // another module's open inventory, the same as a
                        // found declaration.
                        let mut inventory = rows.crate_inventory_completion(
                            &module,
                            target.0,
                            &target.1,
                            sql::namespace(demand.namespace()),
                            &target.2,
                        )?;
                        let bindings = rows.crate_external_bindings(
                            &module,
                            target.0,
                            &target.1,
                            demand.namespace(),
                            &target.2,
                        )?;
                        if !bindings.is_empty() {
                            inventory = ResolutionCompletion::incomplete(bindings.into_iter().map(|semantic|
                                ResolutionIncompleteReason::OpenBoundary {
                                    semantic,
                                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                                }
                            ));
                        }
                        pending_completion =
                            pending_completion.combine(&inventory).combine(&unstaged);
                    }
                    for (export, target_demand, evidence) in exports {
                        let SelectedRootPathHalf::Export {
                            identity,
                            token,
                            demand,
                            definition,
                            ..
                        } = &export
                        else {
                            unreachable!("export query returns sealed exports");
                        };
                        let key = (identity.fragment(), *token, *demand, *definition);
                        match authorities.entry(key) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert((export, target_demand, evidence));
                            }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                let previous = &mut entry.get_mut().2;
                                *previous = if *previous == ResolutionCompletion::Complete
                                    || evidence == ResolutionCompletion::Complete
                                {
                                    ResolutionCompletion::Complete
                                } else {
                                    previous.combine(&evidence)
                                };
                            }
                        }
                    }
                }
                answered_placements += 1;
                if authorities.len() == before {
                    pending_completion = pending_completion.combine(&completion);
                }
            }
            for (export_half, target_demand, evidence) in authorities.values() {
                let SelectedRootPathHalf::Export {
                    identity: export_identity,
                    token: export_token,
                    ..
                } = export_half
                else {
                    unreachable!("export query returns sealed exports");
                };
                let descriptor = if let Some(prefix) = prefix {
                    SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                        identity.fragment(),
                        Language::Rust,
                        token,
                        anchor,
                        anchor_semantic,
                        export_identity.fragment(),
                        Language::Rust,
                        *export_token,
                        prefix,
                        route.to_vec(),
                        demand.clone(),
                        target_demand.clone(),
                        evidence.clone(),
                    )
                } else {
                    SelectedRootBridgeDescriptor::from_selected_path_tokens(
                        identity.fragment(),
                        Language::Rust,
                        token,
                        anchor,
                        anchor_semantic,
                        export_identity.fragment(),
                        Language::Rust,
                        *export_token,
                        route.to_vec(),
                        demand.clone(),
                        target_demand.clone(),
                        evidence.clone(),
                    )
                };
                descriptors
                    .push(descriptor.with_selected_export(&self.ready.shared_names(), export_half));
            }
            let published_member_bridge = !member_bridges.is_empty();
            descriptors.append(&mut member_bridges);
            if authorities.is_empty() && !published_member_bridge {
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
                    None => import_root_name.as_deref(),
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
                let prefix_spelling = match prefix {
                    Some(prefix) if !known_prefix => self
                        .ready
                        .rust_prefix_spellings(
                            &self.ready.lexical_source(),
                            &[prefix],
                            self.cancellation,
                        )?
                        .remove(&prefix),
                    _ => None,
                };
                let type_prefix = prefix.is_some()
                    && !known_prefix
                    && route.is_empty()
                    && super::super::rust_crate_context::route_prefix_is_a_type(
                        self.ready,
                        prefix_spelling.as_deref(),
                        demand.namespace(),
                        &resolved
                            .as_ref()
                            .expect("a prefix has a resolution")
                            .targets,
                        &resolved
                            .as_ref()
                            .expect("a prefix has a resolution")
                            .completion,
                    )?;
                // A half whose fragment places no module was never asked,
                // and an unasked question has no boundary to claim.
                // A prefix an import anchored in this crate binds names a
                // module of this crate, so a route that found nothing did not
                // leave the workspace: no boundary. It is not a decided
                // absence either, because the crate rows cannot yet prove
                // every such walk closed (items declared through macros or
                // re-exported from other crates), so it stays the dead end.
                let bound_in_the_crate = match (prefix, resolved.as_ref()) {
                    (Some(prefix), Some(resolved)) if !known_prefix => {
                        super::super::rust_crate_context::prefix_bound_in_the_crate(
                            self.ready,
                            prefix,
                            resolved,
                            self.cancellation,
                        )?
                    }
                    _ => false,
                };
                let external_root = answered_placements > 0
                    && !route_reached_a_target
                    && !root_names_a_workspace_crate
                    && match prefix {
                        None => root_name.is_some_and(|name| !sql::is_module_anchor(name)),
                        Some(_) => {
                            !known_prefix
                                && !bound_in_the_crate
                                && !type_prefix
                                && resolved.as_ref().is_some_and(
                                    super::super::rust_prefix::rust_prefix_left_the_workspace,
                                )
                        }
                    };
                if external_root {
                    if is_import && !external_type_import_scopes.is_empty() {
                        let mut import_paths = Vec::new();
                        for (blob, scope) in external_type_import_scopes {
                            let Some(paths) = rows.external_type_import_paths_for_binding(
                                blob,
                                scope,
                                demand.spelling(),
                                self.cancellation,
                            )?
                            else {
                                return Ok(None);
                            };
                            import_paths.extend(paths);
                        }
                        self.ready
                            .context_identities
                            .record_rust_external_type_import_paths(token, import_paths);
                    }
                    if external_root_bindings.is_empty() {
                        external_root_bindings.push(token);
                    }
                    pending_completion = pending_completion.combine(
                        &ResolutionCompletion::incomplete(external_root_bindings.into_iter().map(|semantic|
                            ResolutionIncompleteReason::OpenBoundary {
                                semantic,
                                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                            }
                        )),
                    );
                }
                // An unqualified name no scope binds falls through to the
                // crate's implicit prelude (the producer's route-less root
                // reference). When that prelude supplies the name, it is an
                // item of the unindexed std or core crate: an open boundary
                // naming the prelude, never a proved absence.
                if !is_import && prefix.is_none() && route.is_empty() && !external_root {
                    for &topology in &placed_topologies {
                        if let Some(boundary) = sql::prelude_boundary(
                            conn,
                            &self.ready.context_identities,
                            topology,
                            &demand,
                        )? {
                            self.ready
                                .context_identities
                                .record_rust_prelude_reference(token, boundary);
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
                        semantic: token,
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    });
                if let Some(prefix) = prefix
                    && !known_prefix
                    && !claimed_boundary
                    && !type_prefix
                {
                    let rel_path = self
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .map(|mount| mount.persisted_relative_path().to_owned());
                    let prefix_class = super::super::rust_crate_context::classify_route_prefix(
                        self.ready,
                        rel_path.as_deref(),
                        prefix_spelling.as_deref(),
                        resolved.as_ref().expect("a prefix has a resolution"),
                        prefix.ordinal(),
                        route.is_empty(),
                        self.cancellation,
                    )?;
                    pending_completion = pending_completion.combine(
                        &super::super::rust_crate_context::route_dead_end(
                            &self.ready.context_identities,
                            super::super::rust_crate_context::RouteDeadEnd::UnplacedRoutePrefix,
                            rel_path.as_deref(),
                            prefix_spelling.as_deref(),
                            Some(prefix_class),
                            &route,
                            &demand,
                        ),
                    );
                }
                if pending_completion != ResolutionCompletion::Complete {
                    descriptors.push(sql::deadend(
                        identity.fragment(),
                        token,
                        anchor,
                        anchor_semantic,
                        prefix,
                        &route,
                        &demand,
                        pending_completion,
                    ));
                }
            }
        }
        Ok(Some(descriptors))
    }
}

pub(super) const PREFIX_MODULES: &str = "WITH RECURSIVE graph(topology_id) AS (
 SELECT ?3 UNION SELECT target.topology_id FROM graph
 CROSS JOIN rust_crate_dependencies AS dependency USING(topology_id)
 CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
) SELECT placement.topology_id, modules.container_path, authority.blob_id, authority.source_site,
 mount.persisted_relative_path
 FROM selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id=authority.blob_id AND mapping.declaration_id=authority.declaration
 CROSS JOIN code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 LEFT JOIN rust_crate_containers AS modules
  ON modules.topology_id=placement.topology_id
  AND modules.container_path=placement.container_path || '::' || unit.identifier
 WHERE mount.mount_ordinal=?1 AND placement.topology_id IN (SELECT topology_id FROM graph)";

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        (
            "rust_point_demand_modules",
            super::super::rust_crate_rows::MODULES_FOR_BLOB,
            2,
        ),
        (
            "rust_point_demand_reverse_export_names",
            REVERSE_EXPORTED_NAMES,
            4,
        ),
        ("rust_point_demand_prefix_modules", PREFIX_MODULES, 3),
    ]
}
