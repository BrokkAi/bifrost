//! Request-local interface families from selected Go facts, never pair rows.
use super::*;
use crate::analyzer::resolution::{GoInterfaceSatisfaction, GoMethodSatisfaction};
use rusqlite::{OptionalExtension, params};

#[derive(Clone, Debug)]
pub(crate) struct GoFamilyInterface {
    pub(crate) name: String,
    pub(crate) package_id: i64,
    pub(crate) methods: Vec<SemanticId>,
    pub(crate) outcome: GoMethodSatisfaction,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GoMethodFamily {
    pub(crate) interfaces: Vec<GoFamilyInterface>,
}

impl GoMethodFamily {
    pub(crate) fn contains(&self, method: SemanticId) -> bool {
        self.interfaces.iter().any(|interface| {
            interface.outcome == GoMethodSatisfaction::Satisfies
                && interface.methods.contains(&method)
        })
    }

    pub(crate) fn packages(&self) -> Vec<i64> {
        let mut packages = self
            .interfaces
            .iter()
            .filter(|interface| interface.outcome == GoMethodSatisfaction::Satisfies)
            .map(|interface| interface.package_id)
            .collect::<Vec<_>>();
        packages.sort_unstable();
        packages.dedup();
        packages
    }

    pub(crate) fn rename_refusal(&self) -> Option<(&'static str, String)> {
        if self.interfaces.is_empty() {
            return None;
        }
        let proven = self
            .interfaces
            .iter()
            .any(|interface| interface.outcome == GoMethodSatisfaction::Satisfies);
        Some((
            if proven {
                "interface_method_coupling"
            } else {
                "unknown_interface_method_coupling"
            },
            format!(
                "native Go rename cannot rename one member of an interface method family: {:?}",
                self.interfaces
            ),
        ))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    fn go_method_identity(
        &self,
        context_id: i64,
        method: SemanticId,
    ) -> Result<Option<(String, i64)>> {
        let Some(mount) = method.ordinal() else {
            return Ok(None);
        };
        let Some(key) = method.local_key() else {
            return Ok(None);
        };
        self.ready.inventory.connection().query_row(
            "SELECT callable.name,package.package_id
             FROM temp.selected_resolution_mounts AS mount
             JOIN main.resolution_semantic_sites AS semantic ON semantic.blob_id=mount.blob_id
              AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
             JOIN main.source_native_declaration_bridges AS bridge ON bridge.blob_id=semantic.blob_id
              AND bridge.source_site=semantic.source_site
             JOIN main.source_go_callables AS callable ON callable.blob_id=bridge.blob_id
              AND callable.declaration_id=bridge.declaration_id AND callable.is_method=1
             LEFT JOIN temp.selected_go_transient_placements AS placement ON placement.mount_ordinal=mount.mount_ordinal
             JOIN main.go_package_files AS file ON file.file_version_id=coalesce(mount.file_version_id,placement.file_version_id)
             JOIN main.go_package_instances AS package ON package.package_id=file.package_id
              AND package.context_id=?3 AND package.for_test=''
             WHERE mount.mount_ordinal=?1 LIMIT 1",
            params![mount, key, context_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(Into::into)
    }

    pub(crate) fn go_method_family(
        &self,
        context_id: i64,
        target: &CodeUnit,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<GoMethodFamily> {
        if !target.is_function() || self.go_method_identity(context_id, semantic)?.is_none() {
            return Ok(GoMethodFamily::default());
        }
        let connection = self.ready.inventory.connection();
        // A union/type-set term does not introduce a declared interface method.
        // Follow transparent one-child grammar wrappers, admitting only elements
        // that can promote an indexed method from another interface.
        // Keep the selected mount before packages and declarations: the package-first
        // plan repeats the file-scope declaration inventory for every package.
        let mut statement = connection.prepare_cached(
            "WITH RECURSIVE family_embeddings(blob_id,owner_type_id,type_id) AS (
               SELECT DISTINCT embedding.blob_id,embedding.owner_type_id,embedding.type_id
               FROM temp.selected_resolution_mounts AS selected
               JOIN main.source_go_embeddings AS embedding ON embedding.blob_id=selected.blob_id
               WHERE selected.semantic_language='go'
               UNION
               SELECT embedding.blob_id,embedding.owner_type_id,child.child_id
               FROM family_embeddings AS embedding
               JOIN main.source_go_types AS wrapper ON wrapper.blob_id=embedding.blob_id
                AND wrapper.type_id=embedding.type_id AND wrapper.kind IN (8,9,10)
               JOIN main.source_go_type_children AS child ON child.blob_id=wrapper.blob_id
                AND child.type_id=wrapper.type_id AND child.ordinal=0
               WHERE NOT EXISTS (SELECT 1 FROM main.source_go_type_children AS sibling
                 WHERE sibling.blob_id=wrapper.blob_id AND sibling.type_id=wrapper.type_id AND sibling.ordinal=1)
             )
             SELECT DISTINCT mount.mount_ordinal,definition.semantic_key,package.package_id,
                    package.tool_import_path,declaration.name
             FROM temp.selected_resolution_mounts AS mount
             LEFT JOIN temp.selected_go_transient_placements AS placement ON placement.mount_ordinal=mount.mount_ordinal
             CROSS JOIN main.go_package_files AS file ON file.file_version_id=coalesce(mount.file_version_id,placement.file_version_id)
             CROSS JOIN main.go_package_instances AS package ON package.package_id=file.package_id
              AND package.context_id=?1 AND package.for_test='' AND package.provider_kind='workspace'
             CROSS JOIN main.source_go_type_declarations AS declaration ON declaration.blob_id=mount.blob_id
             CROSS JOIN main.source_go_types AS ty ON ty.blob_id=declaration.blob_id
              AND ty.type_id=declaration.type_id AND ty.kind=13
             CROSS JOIN main.source_native_declaration_bridges AS bridge ON bridge.blob_id=declaration.blob_id
              AND bridge.declaration_id=declaration.declaration_id
             CROSS JOIN main.resolution_semantic_sites AS definition ON definition.blob_id=bridge.blob_id
              AND definition.source_site=bridge.source_site AND definition.semantic_role='definition'
             WHERE mount.semantic_language='go' AND declaration.file_scope=1
               AND (EXISTS (SELECT 1 FROM main.source_go_callables AS method INDEXED BY source_go_callables_by_owner
                    WHERE method.blob_id=declaration.blob_id AND method.owner_type_id=declaration.type_id AND method.name=?2)
                 OR EXISTS (SELECT 1 FROM family_embeddings AS embedding
                    JOIN main.source_go_types AS embedded ON embedded.blob_id=embedding.blob_id
                     AND embedded.type_id=embedding.type_id AND embedded.kind IN (0,7,13)
                    WHERE embedding.blob_id=declaration.blob_id AND embedding.owner_type_id=declaration.type_id))"
        )?;
        let interfaces = statement
            .query_map(params![context_id, target.identifier()], |row| {
                Ok((
                    SemanticId::local(row.get(0)?, row.get::<_, u32>(1)?),
                    row.get::<_, i64>(2)?,
                    format!(
                        "{}.{}.{}",
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        target.identifier()
                    ),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        if interfaces.is_empty() {
            return Ok(GoMethodFamily::default());
        }
        let path = crate::path_utils::rel_path_string(target.source());
        let source_role = self
            .go_source_role_for_mount(
                context_id,
                SelectedResolutionMountOrdinal::new(
                    semantic
                        .ordinal()
                        .expect("a selected Go method has a mount"),
                ),
                cancellation,
            )?
            .ok_or_else(|| StoreError::new("Go method family source role is unavailable"))?;
        let prepared = match self.go_file_import_context_with_role(
            context_id,
            &path,
            &source_role,
            cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(context) => *context,
            GoPreparedImportContextOutcome::Cancelled => {
                return Err(StoreError::new("Go method family was cancelled"));
            }
            GoPreparedImportContextOutcome::Unavailable => {
                return Err(StoreError::new(
                    "Go method family import context is unavailable",
                ));
            }
        };
        let context = match self.prepare_context(
            prepared.context,
            cancellation,
            &SelectedResolutionContextMetrics,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Err(StoreError::new("Go method family was cancelled"));
            }
        };
        let blueprint = match self.ready.collect_blueprint(context, cancellation)? {
            SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
            SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                return Err(StoreError::new("Go method family was cancelled"));
            }
        };
        if matches!(
            self.ready.register_context(&blueprint, cancellation)?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Err(StoreError::new("Go method family was cancelled"));
        }
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&lexical);
        let observed_typed = SeamProfiled::observing(&typed);
        let lookup = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
            Language::Go,
            ResolutionNamespace::Callable,
            target.identifier(),
        )
        .semantic(&self.ready.shared_names());
        let owners = interfaces
            .iter()
            .map(|interface| interface.0)
            .collect::<Vec<_>>();
        let outcomes = self.with_go_forward_operation(
            GoForwardOperationContext {
                blueprint: &blueprint,
                demand: prepared.demand,
                caller_path: &path,
                lexical: &observed_lexical,
                typed: &observed_typed,
                cancellation,
                session: &ResolutionSession::unbounded(),
            },
            None,
            |operation| {
                operation.go_method_satisfaction(semantic, lookup, &owners, |method| {
                    self.go_method_identity(context_id, method)
                })
            },
        )?;
        let interfaces = outcomes
            .into_iter()
            .filter_map(
                |GoInterfaceSatisfaction {
                     owner,
                     methods,
                     outcome,
                 }| {
                    if outcome == GoMethodSatisfaction::DoesNotSatisfy {
                        return None;
                    }
                    let (_, package_id, name) = interfaces
                        .iter()
                        .find(|interface| interface.0 == owner)
                        .expect("checked interface belongs to the selected inventory");
                    Some(GoFamilyInterface {
                        name: name.clone(),
                        package_id: *package_id,
                        methods,
                        outcome,
                    })
                },
            )
            .collect();
        Ok(GoMethodFamily { interfaces })
    }
}
