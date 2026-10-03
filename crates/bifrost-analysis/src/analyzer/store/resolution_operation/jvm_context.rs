//! Demand-local Java import composition over exact selected source publications.
//!
//! This is one caller's query. Package and root membership stay in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::{
    FactPageVisitor, SelectedPackageBridgeDescriptor, SelectedResolutionMountContext,
    SelectedRootPathHalf, visit_selected_root_export_half_pages,
    visit_selected_root_import_half_pages,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionConstructionRequirementKind, ResolutionImportRouteKind, ResolutionMemberAccess,
    ResolutionMemberKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_jvm::java::import_split::{JavaImportInventory, prove_java_single_type_import};

// Immutable derivation for the exact Java revision selected by this operation.
const CONTEXT_SELECTION: &str = r#"
SELECT c.context_id
FROM main.jvm_context_revisions AS c
JOIN temp.selected_workspace_revisions AS selected
  ON selected.workspace_id=c.workspace_id AND selected.lang=c.lang
 AND selected.generation=c.generation AND selected.revision=c.revision
WHERE c.lang='java' AND c.derivation_version=1
"#;

// Package rows are source-derived and indexed by the exact canonical package.
// Only mounted versions selected by this operation can supply candidates.
pub(in crate::analyzer::store) const JAVA_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=package.file_version_id
WHERE package.package_name=?1 AND mounted.storage_language='java'
UNION ALL
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id
WHERE mounted.file_version_id IS NULL AND mounted.storage_language='java'
  AND meta.content_package=?1 AND meta.is_complete=1
"#;

// Exact root evidence supports same-project main/test access and positive
// direct reactor dependencies. Unknown models never establish exclusion.
pub(in crate::analyzer::store) const SOURCE_ACCESS: &str = r#"
WITH caller AS (
 SELECT m.*, p.group_id, p.artifact_id, p.version_state, p.version_value
 FROM main.jvm_selected_source_root_files m
 JOIN main.jvm_selected_projects p ON p.context_id=m.context_id AND p.project_id=m.project_id
 WHERE m.context_id=?1 AND
   ((?2 IS NOT NULL AND m.source_file_version_id=?2) OR (?2 IS NULL AND m.rel_path=?3))
), target AS (
 SELECT m.*, p.group_id, p.artifact_id, p.version_state, p.version_value
 FROM main.jvm_selected_source_root_files m
 JOIN main.jvm_selected_projects p ON p.context_id=m.context_id AND p.project_id=m.project_id
 WHERE m.context_id=?1 AND
   ((?4 IS NOT NULL AND m.source_file_version_id=?4) OR (?4 IS NULL AND m.rel_path=?5))
)
SELECT CASE
 WHEN (SELECT count(*) FROM caller)<>1 OR (SELECT count(*) FROM target)<>1 THEN 'unknown'
 WHEN EXISTS(SELECT 1 FROM main.jvm_selected_context_gaps g WHERE g.context_id=?1
             AND g.project_id IN (caller.project_id,target.project_id)) THEN 'unknown'
 WHEN caller.pom_path=target.pom_path AND caller.pom_content_oid=target.pom_content_oid
 THEN CASE WHEN caller.role='main' AND target.role='test' THEN 'excluded' ELSE 'known' END
 WHEN target.role='main' AND target.version_state='resolved' AND EXISTS(
   SELECT 1 FROM main.jvm_direct_dependencies d
   WHERE d.context_id=?1 AND d.project_id=caller.project_id
     AND d.group_id_state='resolved' AND d.group_id_value=target.group_id
     AND d.artifact_id_state='resolved' AND d.artifact_id_value=target.artifact_id
     AND d.version_state='resolved' AND d.version_value=target.version_value
     AND (d.artifact_type_state='missing' OR (d.artifact_type_state='resolved' AND d.artifact_type_value='jar'))
     AND (d.classifier_state='missing' OR (d.classifier_state='resolved' AND d.classifier_value=''))
     AND (d.scope_state='missing' OR (d.scope_state='resolved' AND
          (d.scope_value IN ('compile','provided') OR (d.scope_value='test' AND caller.role='test'))))
 ) THEN 'known'
 ELSE 'unknown' END
FROM caller CROSS JOIN target
"#;

pub(crate) enum JavaImportContext {
    Ready {
        context: Box<SelectedResolutionContextSet>,
        external_static_imports: Vec<JavaExternalStaticImportBoundary>,
        inventory_reason: SemanticId,
    },
    Unavailable,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JavaExternalStaticImportBoundary {
    pub member: String,
    pub owner: String,
}

#[derive(Clone, Copy)]
enum JavaPackageRelation {
    Same,
    Different,
    Unknown,
}
impl JavaPackageRelation {
    fn between(caller: Option<&str>, target: &str) -> Self {
        match caller {
            Some(package) if package == target => Self::Same,
            Some(_) => Self::Different,
            None => Self::Unknown,
        }
    }
}

enum JavaDeclarationAccess {
    Ready(ResolutionCompletion),
    Excluded,
    Cancelled,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Compose Java type and static source imports for one file.
    /// Inherited routes, peer-language routes and external inventory remain open.
    pub(crate) fn java_import_context(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JavaImportContext> {
        Ok(self
            .java_import_context_parts(caller_path, cancellation)?
            .with_open_inventory_gap())
    }

    /// Compose the same structured imports for inverse confirmation. Its
    /// selected candidate inventory and per-reference forward proof own the
    /// relevant absence questions, so the blanket point-lookup gap is omitted.
    pub(crate) fn java_reverse_import_context(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JavaImportContext> {
        self.java_import_context_parts(caller_path, cancellation)
    }

    fn java_import_context_parts(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JavaImportContext> {
        if cancellation.is_cancelled() {
            return Ok(JavaImportContext::Cancelled);
        }
        let connection = self.ready.inventory.connection();
        let selected = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([], |row| row.get::<_, i64>(0))
            .optional()?;
        let Some(context_id) = selected else {
            return Ok(JavaImportContext::Unavailable);
        };
        let Some(source) = self.mount_table().mount_for_path("java", caller_path)? else {
            return Ok(JavaImportContext::Unavailable);
        };
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let file_version = source_record.file_version_id();
        // Package identity belongs to the selected content, including unsaved
        // replacements. Source-root/classpath access remains separately proven.
        let source_package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [source_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let identities = self.ready.context_identities.clone();
        let evidence = "JVM selected source facts leave effective classpath, external artifacts, inherited imports and peer-language routes open";
        let mut hash = CanonicalHasher::new(b"bifrost-java-context-incomplete:v1");
        hash.field("context", &context_id.to_le_bytes());
        let reason = identities.named_semantic(hash.finish(), "java-context-incomplete", evidence);
        let completion = ResolutionCompletion::Complete;
        let lexical = self.ready.lexical_source();
        let mut imports = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source.ordinal()]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                imports.extend_from_slice(page);
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(JavaImportContext::Cancelled);
        }
        // Inventory uncertainty describes routes we have not enumerated. A
        // positive source bridge carries its own source/declaration access
        // evidence; unrelated inventory gaps must not taint that witness.
        let mut bridges = Vec::new();
        let mut external_static_imports = Vec::new();
        let mut indexed_static_import_members = Vec::new();
        for import in imports {
            let SelectedRootPathHalf::Import {
                route,
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = import
            else {
                continue;
            };
            let (runtime_key, shared_id) =
                super::super::resolution_stage::lexical::semantic_cells(token);
            let staged = connection.query_row(
                "SELECT c.import_route_kind FROM temp.selected_resolution_stage_semantic_coordinates c
                 JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=c.host_ordinal
                 WHERE c.runtime_key IS ?1 AND c.shared_id IS ?2 AND c.host_ordinal=?3",
                rusqlite::params![runtime_key, shared_id, source.ordinal().get()],
                |row| row.get::<_,Option<String>>(0),
            ).optional()?;
            let kind = if let Some(kind) = staged {
                kind
            } else if let Some(token_key) = token.local_key() {
                connection.query_row(
                    "SELECT import_route_kind FROM main.resolution_semantic_catalog WHERE blob_id=?1 AND local_key=?2",
                    rusqlite::params![source_record.blob_id(), token_key], |row| row.get::<_,Option<String>>(0),
                ).optional()?.flatten()
            } else {
                None
            };
            if !matches!(
                kind.as_deref(),
                Some("single_type" | "type_on_demand" | "single_static" | "static_on_demand")
            ) {
                // Actual token provenance is required before composing an import.
                continue;
            }
            let import_kind = match kind.as_deref() {
                Some("single_type") => ResolutionImportRouteKind::SingleType,
                Some("type_on_demand") => ResolutionImportRouteKind::TypeOnDemand,
                Some("single_static") => ResolutionImportRouteKind::SingleStatic,
                Some("static_on_demand") => ResolutionImportRouteKind::StaticOnDemand,
                _ => unreachable!("Java import kind was checked above"),
            };
            let mut semantics = route.into_vec();
            semantics.push(demand);
            let mut recipes = Vec::with_capacity(semantics.len());
            for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
                let requests = page
                    .iter()
                    .map(|&semantic| SelectedLookupRecipeRequest {
                        fragment: source.fragment(),
                        semantic,
                    })
                    .collect::<Vec<_>>();
                let SelectedLookupRecipeReadOutcome::Ready(rows) =
                    lexical.lookup_semantic_recipes(&requests, cancellation, None)?
                else {
                    return Ok(JavaImportContext::Cancelled);
                };
                for recipe in rows {
                    recipes.push(recipe.ok_or_else(|| {
                        StoreError::corrupt("selected Java root lookup has no shared recipe")
                    })?);
                }
            }
            let demand_recipe = recipes.pop().expect("one import demand");
            let mut owner_found = false;
            let Some(members) = self.java_type_member_import_candidates(
                context_id,
                file_version,
                &JavaMemberImportDemand {
                    import_kind: Some(import_kind),
                    source: source.fragment(),
                    caller_package: source_package.as_deref(),
                    token,
                    prefix_reference: None,
                    anchor,
                    anchor_semantic,
                    route: &recipes,
                    demand: &demand_recipe,
                },
                &ResolutionCompletion::Complete,
                cancellation,
                &mut owner_found,
            )?
            else {
                return Ok(JavaImportContext::Cancelled);
            };
            match kind.as_deref() {
                Some("single_static" | "static_on_demand") => {
                    let member = demand_recipe.spelling().to_string();
                    if owner_found {
                        indexed_static_import_members.push(member.clone());
                    } else {
                        let owner = recipes
                            .iter()
                            .map(ResolutionLookupSemanticRecipe::spelling)
                            .collect::<Vec<_>>()
                            .join(".");
                        if !owner.is_empty() {
                            external_static_imports
                                .push(JavaExternalStaticImportBoundary { member, owner });
                        }
                    }
                    let Some(static_members) =
                        self.java_static_import_bridges(members, cancellation)?
                    else {
                        return Ok(JavaImportContext::Cancelled);
                    };
                    bridges.extend(static_members);
                    continue;
                }
                Some("single_type") => {
                    let path = recipes
                        .iter()
                        .map(|recipe| recipe.spelling().to_owned())
                        .chain(std::iter::once(demand_recipe.spelling().to_owned()))
                        .collect::<Vec<_>>();
                    let candidate_units = members
                        .iter()
                        .map(|member| member.unit.clone())
                        .collect::<Vec<_>>();
                    let proof = prove_java_single_type_import(
                        &path,
                        JavaImportInventory::partial(&|name| {
                            candidate_units
                                .iter()
                                .filter(|unit| unit.fq_name() == name)
                                .cloned()
                                .collect()
                        }),
                    );
                    let targets = proof.targets();
                    bridges.extend(
                        members
                            .into_iter()
                            .filter(|member| targets.contains(&member.unit))
                            .map(|member| member.bridge),
                    );
                }
                Some("type_on_demand") => {
                    bridges.extend(members.into_iter().map(|member| member.bridge));
                }
                _ => unreachable!("import kind was checked above"),
            }
            let Some(package_bridges) = self.java_package_type_import_bridges(
                context_id,
                file_version,
                &JavaMemberImportDemand {
                    import_kind: Some(import_kind),
                    source: source.fragment(),
                    caller_package: source_package.as_deref(),
                    token,
                    prefix_reference: None,
                    anchor,
                    anchor_semantic,
                    route: &recipes,
                    demand: &demand_recipe,
                },
                &ResolutionCompletion::Complete,
                cancellation,
            )?
            else {
                return Ok(JavaImportContext::Cancelled);
            };
            bridges.extend(package_bridges);
        }
        let SelectedPackageRows::Ready(package_references) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(JavaImportContext::Cancelled);
        };
        let mut package_bridges = Vec::new();
        for package in source_package.iter() {
            let mut statement = connection.prepare_cached(JAVA_IMPORT_TARGET_MOUNTS)?;
            let targets = statement
                .query_map([package], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?))
                })?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?;
            for (target, target_file_version) in targets {
                if cancellation.is_cancelled() {
                    return Ok(JavaImportContext::Cancelled);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(target);
                if ordinal == source.ordinal() {
                    continue;
                }
                let target_mount = self.mount_table().mount_by_ordinal(ordinal)?;
                let Some(access) = self.java_source_access_completion(
                    context_id,
                    file_version,
                    source.persisted_relative_path(),
                    target_file_version,
                    target_mount.persisted_relative_path(),
                    &ResolutionCompletion::Complete,
                )?
                else {
                    continue;
                };
                for reference in &package_references {
                    let SelectedPackageRows::Ready(members) = self
                        .selected_package_members_for_lookup(
                            ordinal,
                            reference.lookup,
                            cancellation,
                        )?
                    else {
                        return Ok(JavaImportContext::Cancelled);
                    };
                    for member in members {
                        if member.domain != reference.domain
                            || member.namespace != reference.namespace
                        {
                            continue;
                        }
                        let access = match self.java_declaration_access(
                            member.definition,
                            JavaPackageRelation::Same,
                            &access,
                            cancellation,
                        )? {
                            JavaDeclarationAccess::Ready(completion) => completion,
                            JavaDeclarationAccess::Excluded => continue,
                            JavaDeclarationAccess::Cancelled => {
                                return Ok(JavaImportContext::Cancelled);
                            }
                        };
                        package_bridges.push(SelectedPackageBridgeDescriptor::new(
                            source.fragment(),
                            target_mount.fragment(),
                            Language::Java,
                            reference,
                            &member,
                            access,
                        ));
                    }
                }
            }
        }
        let mount = SelectedResolutionMountContext::new(
            source.ordinal(),
            source.fragment(),
            Language::Java,
            bridges,
            completion,
        )?
        .with_package_bridges(package_bridges)?;
        let mounts = self.mount_table();
        let context = SelectedResolutionContextSet::new(
            identities,
            vec![mount],
            mounts.mount_count(),
            &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            },
        )?;
        let access_identity = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"java-selected-declaration-access:v1").finish(),
            "java-selected-declaration-access",
            "Java declaration visibility under exact selected package and lexical ownership",
        );
        external_static_imports
            .retain(|boundary| !indexed_static_import_members.contains(&boundary.member));
        external_static_imports
            .sort_by(|left, right| (&left.member, &left.owner).cmp(&(&right.member, &right.owner)));
        external_static_imports.dedup();
        Ok(JavaImportContext::Ready {
            context: Box::new(context.with_declaration_access_source(Arc::new(
                super::java_access::JavaAccessPolicy {
                    identity: access_identity,
                },
            ))),
            external_static_imports,
            inventory_reason: reason,
        })
    }
    fn java_source_access_completion(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ResolutionCompletion>> {
        if caller_path == target_path {
            // A declaration in the exact caller file is source-accessible
            // without project or source-root ownership facts.
            return Ok(Some(completion.clone()));
        }
        let connection = self.ready.inventory.connection();
        let access = connection
            .query_row(
                SOURCE_ACCESS,
                rusqlite::params![context, caller, caller_path, target, target_path],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| "unknown".to_owned());
        match access.as_str() {
            "excluded" => Ok(None),
            "known" => Ok(Some(completion.clone())),
            "unknown" => {
                let mut hash = CanonicalHasher::new(b"bifrost-java-source-access-open:v1");
                hash.field("context", &context.to_le_bytes());
                if let Some(caller) = caller {
                    hash.field("caller", &caller.to_le_bytes());
                }
                if let Some(target) = target {
                    hash.field("target", &target.to_le_bytes());
                }
                let gap = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "java-source-access-open",
                    "Selected Maven root/dependency facts do not establish this source visibility",
                );
                Ok(Some(completion.combine(&ResolutionCompletion::incomplete(
                    [ResolutionIncompleteReason::UnsupportedSemantic(gap)],
                ))))
            }
            _ => unreachable!("source access SQL has three outcomes"),
        }
    }

    fn java_declaration_access(
        &self,
        definition: SemanticId,
        package: JavaPackageRelation,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<JavaDeclarationAccess> {
        let mut visibilities = Vec::new();
        let outcome = self
            .ready
            .typed_source()
            .visit_declaration_visibility_pages_for_definitions(
                TypedFactRequest::new(&[definition]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    visibilities.extend(page.iter().map(|row| row.row().visibility()));
                    Ok(true)
                }),
            )?;
        if outcome.is_cancelled() {
            return Ok(JavaDeclarationAccess::Cancelled);
        }
        let known = match (visibilities.as_slice(), package) {
            ([DeclaredVisibility::Public], _) => true,
            // Imports are outside a subclass body, so protected access cannot
            // authorize a cross-package import even when a declared class in
            // the caller later extends the member's owner.
            (
                [DeclaredVisibility::PackagePrivate | DeclaredVisibility::Protected],
                JavaPackageRelation::Different,
            )
            | ([DeclaredVisibility::Private], _) => return Ok(JavaDeclarationAccess::Excluded),
            (
                [DeclaredVisibility::PackagePrivate | DeclaredVisibility::Protected],
                JavaPackageRelation::Same,
            ) => true,
            _ => false,
        };
        if known {
            return Ok(JavaDeclarationAccess::Ready(completion.clone()));
        }
        let gap = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"java-import-declaration-visibility-open:v1").finish(),
            "java-import-declaration-visibility-open",
            "Selected declaration visibility does not establish import access",
        );
        Ok(JavaDeclarationAccess::Ready(completion.combine(
            &ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                gap,
            )]),
        )))
    }
}

impl JavaImportContext {
    fn with_open_inventory_gap(self) -> Self {
        match self {
            Self::Ready {
                context,
                external_static_imports,
                inventory_reason,
            } => Self::Ready {
                context: Box::new(
                    (*context).with_additional_context_owned_inventory_reason(inventory_reason),
                ),
                external_static_imports,
                inventory_reason,
            },
            Self::Unavailable => Self::Unavailable,
            Self::Cancelled => Self::Cancelled,
        }
    }
}

struct JavaMemberImportDemand<'a> {
    import_kind: Option<ResolutionImportRouteKind>,
    caller_package: Option<&'a str>,
    source: BindingFragmentId,
    token: SemanticId,
    prefix_reference: Option<SemanticId>,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    route: &'a [ResolutionLookupSemanticRecipe],
    demand: &'a ResolutionLookupSemanticRecipe,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Query-owned direct member continuation. Package prefixes come from
    /// exact selected package rows; each remaining segment must name a member
    /// of the already-proven type. Inherited routes remain incomplete.
    fn java_type_member_import_candidates(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        owner_found: &mut bool,
    ) -> Result<Option<Vec<JavaImportMemberCandidate>>> {
        let connection = self.ready.inventory.connection();
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let names = self.ready.shared_names();
        let mut bridges = Vec::new();
        // An imported type cannot be in the unnamed package. The final route
        // segment is an enclosing type here; ordinary package imports are
        // composed separately by the caller.
        for package_length in 1..import.route.len() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let package = import.route[..package_length]
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            let outer_lookup = ResolutionLookupSemanticRecipe::new(
                Language::Java,
                ResolutionNamespace::Type,
                import.route[package_length].spelling(),
            )
            .semantic(&names);
            let mut statement = connection.prepare_cached(JAVA_IMPORT_TARGET_MOUNTS)?;
            let targets = statement
                .query_map([&package], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let relation = JavaPackageRelation::between(import.caller_package, &package);
            let caller_mount = self
                .mount_table()
                .mount_for_fragment(import.source)?
                .expect("Java import source remains selected");
            for (ordinal, version) in targets {
                let target_ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let access = self.java_source_access_completion(
                    context,
                    caller_version,
                    caller_mount.persisted_relative_path(),
                    version,
                    target_mount.persisted_relative_path(),
                    completion,
                )?;
                let Some(access) = access else {
                    continue;
                };
                let target = target_ordinal;
                let mut exports = Vec::new();
                let outcome = visit_selected_root_export_half_pages(
                    &self.ready.context_identities,
                    &lexical,
                    &lexical,
                    Some(&[target]),
                    cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        exports.extend(page.iter().filter(|half| matches!(half, SelectedRootPathHalf::Export { demand, .. } if *demand == outer_lookup)).cloned());
                        Ok(true)
                    }),
                )?;
                if outcome.is_cancelled() {
                    return Ok(None);
                }
                for export in exports {
                    let nested_route = &import.route[package_length + 1..];
                    if nested_route.is_empty() {
                        *owner_found = true;
                    }
                    let SelectedRootPathHalf::Export {
                        identity,
                        token,
                        definition,
                        incomplete_reasons,
                        ..
                    } = export
                    else {
                        unreachable!("export-only visitor");
                    };
                    let endpoints = lexical.classify_endpoint_nodes(&[definition], cancellation)?;
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let owner = endpoints
                        .first()
                        .and_then(|row| row.definition())
                        .ok_or_else(|| {
                            StoreError::corrupt("Java enclosing export lacks definition")
                        })?;
                    let access = match self.java_declaration_access(
                        owner,
                        relation,
                        &access,
                        cancellation,
                    )? {
                        JavaDeclarationAccess::Ready(access) => {
                            if incomplete_reasons.is_empty() {
                                access
                            } else {
                                access.combine(&ResolutionCompletion::incomplete(
                                    incomplete_reasons.iter().copied(),
                                ))
                            }
                        }
                        JavaDeclarationAccess::Excluded => continue,
                        JavaDeclarationAccess::Cancelled => return Ok(None),
                    };
                    let target_mount = self.mount_table().mount_by_ordinal(target)?;
                    let target_file = ProjectFile::new(
                        self.ready.project.root().to_path_buf(),
                        target_mount.persisted_relative_path(),
                    );
                    let mut owners = vec![(
                        owner,
                        access,
                        ResolutionMemberAccess::Type,
                        None::<CodeUnit>,
                    )];
                    // Every step is iterative, including deeply nested types.
                    for (step, (name, namespace)) in nested_route
                        .iter()
                        .map(|recipe| (recipe.spelling(), ResolutionNamespace::Type))
                        .chain(std::iter::once((
                            import.demand.spelling(),
                            import.demand.namespace(),
                        )))
                        .enumerate()
                    {
                        let mut next = BTreeMap::new();
                        for (owner, access, _, _) in owners {
                            let mut members = Vec::new();
                            let outcome = typed.visit_member_owner_pages_for_owners(
                                TypedFactRequest::new(&[owner]),
                                cancellation,
                                &mut FactPageVisitor::new(&mut |page| {
                                    members.extend(
                                        page.iter()
                                            .filter(|row| {
                                                matches!(
                                                    (namespace, row.row().kind()),
                                                    (
                                                        ResolutionNamespace::Type,
                                                        ResolutionMemberKind::NestedType
                                                    ) | (
                                                        ResolutionNamespace::Value,
                                                        ResolutionMemberKind::Field
                                                    ) | (
                                                        ResolutionNamespace::Callable,
                                                        ResolutionMemberKind::Method
                                                    )
                                                )
                                            })
                                            .map(|row| {
                                                (row.row().definition(), row.row().access())
                                            }),
                                    );
                                    Ok(true)
                                }),
                            )?;
                            if outcome.is_cancelled() {
                                return Ok(None);
                            }
                            members.sort_unstable_by_key(|(definition, _)| *definition);
                            members.dedup();
                            let member_access: BTreeMap<_, _> = members.iter().copied().collect();
                            let coordinates = members
                                .into_iter()
                                // Stage-only declarations lacking a parser-unit
                                // crosswalk stay inside the retained open gap.
                                .filter(|(member, _)| member.ordinal() == Some(ordinal))
                                .filter_map(|(member, _)| {
                                    member.local_key().map(|key| {
                                        (target, ResolutionLocalKey::new(i64::from(key)))
                                    })
                                })
                                .collect::<Vec<_>>();
                            for chunk in coordinates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                                let SelectedDefinitionUnitReadOutcome::Ready(rows) = self
                                    .ready
                                    .inventory
                                    .selected_declaration_units(chunk, cancellation)?
                                else {
                                    return Ok(None);
                                };
                                for (_, key, row) in rows {
                                    let identity = row.fq.as_ref().ok_or_else(|| {
                                        StoreError::corrupt(
                                            "selected Java member lacks structured name",
                                        )
                                    })?;
                                    if identity
                                        .segments
                                        .last()
                                        .is_none_or(|(_, spelling)| spelling != name)
                                    {
                                        continue;
                                    }
                                    if step + 1 == nested_route.len()
                                        && namespace == ResolutionNamespace::Type
                                    {
                                        *owner_found = true;
                                    }
                                    let member = SemanticId::local(
                                        ordinal,
                                        u32::try_from(key.get())
                                            .expect("a catalog position fits u32"),
                                    );
                                    let access = match self.java_declaration_access(
                                        member,
                                        relation,
                                        &access,
                                        cancellation,
                                    )? {
                                        JavaDeclarationAccess::Ready(access) => access,
                                        JavaDeclarationAccess::Excluded => continue,
                                        JavaDeclarationAccess::Cancelled => return Ok(None),
                                    };
                                    let (fq, package_segments) =
                                        super::super::hydrate_unit_fq_with_anchor(
                                            Some(identity),
                                            &row.content_qualifier,
                                            &target_file,
                                            |_, _, _| None,
                                        )?;
                                    let unit = CodeUnit::from_fq(
                                        target_file.clone(),
                                        row.kind,
                                        fq,
                                        package_segments,
                                        row.signature.clone(),
                                        row.flags.synthetic,
                                    );
                                    next.entry(member)
                                        .and_modify(
                                            |previous: &mut (
                                                ResolutionCompletion,
                                                ResolutionMemberAccess,
                                                CodeUnit,
                                            )| {
                                                previous.0 = previous.0.combine(&access);
                                                assert_eq!(previous.2, unit);
                                            },
                                        )
                                        .or_insert((access, member_access[&member], unit));
                                }
                            }
                        }
                        owners = next
                            .into_iter()
                            .map(|(member, (completion, access, unit))| {
                                (member, completion, access, Some(unit))
                            })
                            .collect();
                        if owners.is_empty() {
                            break;
                        }
                    }
                    for (member, access, member_access, unit) in owners {
                        let Some(node) = lexical.lookup_definition_node(member, cancellation)?
                        else {
                            if cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            return Err(StoreError::corrupt(
                                "selected Java member lacks definition node",
                            ));
                        };
                        bridges.push(JavaImportMemberCandidate {
                            definition: member,
                            access: member_access,
                            unit: unit.expect("selected import endpoint has a source CodeUnit"),
                            bridge: import
                                .bridge(identity.fragment(), token, access)
                                .with_selected_member_definition(node),
                        });
                    }
                }
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(bridges))
    }
}

/// A selected member before the source import's static-access rule is applied.
struct JavaImportMemberCandidate {
    definition: SemanticId,
    access: ResolutionMemberAccess,
    unit: CodeUnit,
    bridge: SelectedRootBridgeDescriptor,
}

impl SelectedResolutionOperation<'_, '_> {
    fn java_static_import_bridges(
        &self,
        members: Vec<JavaImportMemberCandidate>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let typed = self.ready.typed_source();
        let mut bridges = Vec::new();
        for member in members {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if member.access != ResolutionMemberAccess::Type {
                continue;
            }
            // Nested-type lookup uses Type access even for inner classes.
            // Their construction requirement distinguishes them from static
            // nested classes, interfaces, enums and records.
            let mut requires_instance = false;
            let outcome = typed.visit_construction_requirement_pages_for_definitions(
                TypedFactRequest::new(&[member.definition]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    requires_instance |= page.iter().any(|row| {
                        row.row().kind() == ResolutionConstructionRequirementKind::EnclosingInstance
                    });
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            if !requires_instance {
                bridges.push(member.bridge);
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(bridges))
    }
}

impl JavaMemberImportDemand<'_> {
    fn bridge(
        &self,
        target: BindingFragmentId,
        export_token: SemanticId,
        completion: ResolutionCompletion,
    ) -> SelectedRootBridgeDescriptor {
        if let Some(prefix) = self.prefix_reference {
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                self.source,
                Language::Java,
                self.token,
                self.anchor,
                self.anchor_semantic,
                target,
                Language::Java,
                export_token,
                prefix,
                self.route.to_vec(),
                self.demand.clone(),
                self.demand.clone(),
                completion,
            )
        } else {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                self.source,
                Language::Java,
                self.token,
                self.anchor,
                self.anchor_semantic,
                target,
                Language::Java,
                export_token,
                self.route.to_vec(),
                self.demand.clone(),
                self.demand.clone(),
                completion,
            )
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    fn java_package_type_import_bridges(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let connection = self.ready.inventory.connection();
        let lexical = self.ready.lexical_source();
        let identities = &self.ready.context_identities;
        let demand = import.demand.semantic(&self.ready.shared_names());
        let mut bridges = Vec::new();
        let spelling = import
            .route
            .iter()
            .map(ResolutionLookupSemanticRecipe::spelling)
            .collect::<Vec<_>>()
            .join(".");
        let mut statement = connection.prepare_cached(JAVA_IMPORT_TARGET_MOUNTS)?;
        let rows = statement.query_map([&spelling], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?))
        })?;
        let targets = rows.collect::<rusqlite::Result<BTreeSet<_>>>()?;
        let mut admitted_target = false;
        let caller_mount = self
            .mount_table()
            .mount_for_fragment(import.source)?
            .expect("Java import source remains selected");
        for (target, target_file_version) in targets {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal = SelectedResolutionMountOrdinal::new(target);
            let target_mount = self.mount_table().mount_by_ordinal(ordinal)?;
            let bridge_completion = self.java_source_access_completion(
                context,
                caller_version,
                caller_mount.persisted_relative_path(),
                target_file_version,
                target_mount.persisted_relative_path(),
                completion,
            )?;
            let Some(bridge_completion) = bridge_completion else {
                continue;
            };
            let mut exports = Vec::new();
            let outcome = visit_selected_root_export_half_pages(
                identities,
                &lexical,
                &lexical,
                Some(&[ordinal]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    exports.extend_from_slice(page);
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            for export in exports {
                let SelectedRootPathHalf::Export {
                    identity,
                    token: export_token,
                    demand: export_demand,
                    definition,
                    ..
                } = &export
                else {
                    unreachable!("export-only visitor")
                };
                if *export_demand != demand || admitted_target {
                    continue;
                }
                let endpoints = lexical.classify_endpoint_nodes(&[*definition], cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let definition_semantic = endpoints
                    .first()
                    .and_then(|endpoint| endpoint.definition())
                    .ok_or_else(|| {
                        StoreError::corrupt("Java export lacks a declaration endpoint")
                    })?;
                let relation = JavaPackageRelation::between(import.caller_package, &spelling);
                let bridge_completion = match self.java_declaration_access(
                    definition_semantic,
                    relation,
                    &bridge_completion,
                    cancellation,
                )? {
                    JavaDeclarationAccess::Ready(completion) => completion,
                    JavaDeclarationAccess::Excluded => continue,
                    JavaDeclarationAccess::Cancelled => {
                        return Ok(None);
                    }
                };
                // This exact package/name lookup has one top-level type
                // segment shape. Repeated source roots mirror that same
                // declaration shape; keep the index-preferred first target.
                // Nested readings are composed separately by the owner walk.
                bridges.push(
                    import
                        .bridge(identity.fragment(), *export_token, bridge_completion)
                        .with_selected_export(&self.ready.shared_names(), &export),
                );
                admitted_target = true;
            }
        }
        Ok(Some(bridges))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn java_qualified_type_bridges(
        &self,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference,
            route,
            token,
            anchor,
            anchor_semantic,
            demand,
            ..
        } = half
        else {
            unreachable!("qualified Java demand has a reference half");
        };
        let mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let context: i64 = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([], |row| row.get(0))?;
        let package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let lexical = self.ready.lexical_source();
        let mut recipes = Vec::new();
        let semantics = route
            .iter()
            .copied()
            .chain(std::iter::once(*demand))
            .collect::<Vec<_>>();
        for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            let requests = page
                .iter()
                .map(|&semantic| SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic,
                })
                .collect::<Vec<_>>();
            let SelectedLookupRecipeReadOutcome::Ready(rows) =
                lexical.lookup_semantic_recipes(&requests, cancellation, None)?
            else {
                return Ok(None);
            };
            for recipe in rows {
                recipes.push(recipe.ok_or_else(|| {
                    StoreError::corrupt("selected Java qualified lookup lacks recipe")
                })?);
            }
        }
        let demand = recipes.pop().expect("qualified type demand");
        let import = JavaMemberImportDemand {
            import_kind: None,
            caller_package: package.as_deref(),
            source: identity.fragment(),
            token: *token,
            prefix_reference: *prefix_reference,
            anchor: *anchor,
            anchor_semantic: *anchor_semantic,
            route: &recipes,
            demand: &demand,
        };
        let Some(mut bridges) = self.java_package_type_import_bridges(
            context,
            record.file_version_id(),
            &import,
            completion,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut owner_found = false;
        let Some(members) = self.java_type_member_import_candidates(
            context,
            record.file_version_id(),
            &import,
            completion,
            cancellation,
            &mut owner_found,
        )?
        else {
            return Ok(None);
        };
        bridges.extend(members.into_iter().map(|member| member.bridge));
        Ok(Some(bridges))
    }
}
