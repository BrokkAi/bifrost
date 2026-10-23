//! Exact selected Java ownership for declaration-access decisions.

use super::*;
use crate::analyzer::resolution::{JavaAccessEndpoint, JvmAccessEndpoint};
use crate::hash::{HashMap, HashSet};

// Each seed and parent lookup is keyed by one selected blob and semantic. UNION
// also bounds malformed cyclic ownership without recursive Rust traversal.
pub(in crate::analyzer::store) const ENDPOINTS: &str = r#"
WITH RECURSIVE seeds(mount_ordinal, semantic_key, blob_id, package, owner) AS (
 SELECT request.mount_ordinal, request.key0, mount.blob_id, meta.content_package,
        CASE semantic.semantic_role WHEN 'definition' THEN request.key0 ELSE NULLIF(site.owner, -1) END
 FROM temp.selected_resolution_typed_requests_1 AS request
 CROSS JOIN temp.selected_resolution_mounts AS mount
   ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language='java'
 CROSS JOIN main.resolution_fragment_interiors AS interior
   ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
  AND interior.semantic_language=mount.semantic_language
  AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
  AND interior.publication_state='complete'
 CROSS JOIN main.resolution_sites AS site
   ON site.blob_id=mount.blob_id AND site.site=request.key0
 CROSS JOIN main.resolution_semantic_sites AS semantic
   ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=request.key0
  AND semantic.semantic_role=CASE site.role WHEN 0 THEN 'reference' ELSE 'definition' END
 CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id AND meta.is_complete=1
), owners(mount_ordinal, semantic_key, blob_id, package, owner) AS (
 SELECT mount_ordinal, semantic_key, blob_id, package, owner FROM seeds
 UNION
 SELECT owners.mount_ordinal, owners.semantic_key, owners.blob_id, owners.package,
        parent.owner_definition_semantic_key
 FROM owners
 CROSS JOIN main.resolution_member_owner_properties AS parent
   ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
)
SELECT owners.mount_ordinal, owners.semantic_key, owners.package, owners.owner,
       CASE WHEN parent.definition_semantic_key IS NULL
                 AND scope.definition_semantic_key IS NOT NULL THEN owners.owner END
FROM owners
LEFT JOIN main.resolution_member_owner_properties AS parent
  ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
LEFT JOIN main.resolution_member_scope_properties AS scope
  ON scope.blob_id=owners.blob_id AND scope.definition_semantic_key=owners.owner AND scope.scope_kind='type_body'
"#;

// The owner chain is returned as parent rows. Rust follows that selected
// chain from the exact seed to collect enclosing templates in lexical order;
// keeping the recursive CTE's UNION key free of depth also bounds malformed
// owner cycles.
//
// `resolution_sites.owner` is -1 for a reference that sits in no declaration (an
// import selector at file level) and NULL when the producer published no
// ownership at all. This read returns the owner as an optional semantic key, so
// the stored -1 is decoded to NULL here: such a reference has no enclosing
// template, which is what an absent seed owner means to the caller.
pub(in crate::analyzer::store) const JVM_ENDPOINTS: &str = r#"
WITH RECURSIVE seeds(mount_ordinal, semantic_key, blob_id, language, package, owner, seed_owner, semantic_role) AS (
 SELECT request.mount_ordinal, request.key0, mount.blob_id, mount.semantic_language,
        CASE WHEN mount.semantic_language='scala' THEN (
          SELECT prefix.prefix
          FROM main.source_native_declaration_bridges AS bridge
          JOIN main.source_scala_declaration_lexical_prefixes AS prefix
            ON prefix.blob_id=bridge.blob_id AND prefix.declaration_id=bridge.declaration_id
          WHERE bridge.blob_id=mount.blob_id
            AND bridge.source_site=CASE semantic.semantic_role WHEN 'definition' THEN site.site ELSE NULLIF(site.owner,-1) END
          ORDER BY prefix.ordinal DESC LIMIT 1
        ) ELSE meta.content_package END,
        CASE semantic.semantic_role WHEN 'definition' THEN request.key0 ELSE NULLIF(site.owner, -1) END,
        CASE semantic.semantic_role WHEN 'definition' THEN request.key0 ELSE NULLIF(site.owner, -1) END,
        semantic.semantic_role
 FROM temp.selected_resolution_typed_requests_1 AS request
 CROSS JOIN temp.selected_resolution_mounts AS mount
   ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language IN ('java','scala')
 CROSS JOIN main.resolution_fragment_interiors AS interior
   ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
  AND interior.semantic_language=mount.semantic_language
  AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
  AND interior.publication_state='complete'
 CROSS JOIN main.resolution_sites AS site
   ON site.blob_id=mount.blob_id AND site.site=request.key0
 CROSS JOIN main.resolution_semantic_sites AS semantic
   ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=request.key0
  AND semantic.semantic_role=CASE site.role WHEN 0 THEN 'reference' ELSE 'definition' END
 CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id AND meta.is_complete=1
), owners(mount_ordinal, semantic_key, blob_id, language, package, owner, seed_owner, semantic_role) AS (
 SELECT mount_ordinal, semantic_key, blob_id, language, package, owner, seed_owner, semantic_role FROM seeds
 UNION
 SELECT owners.mount_ordinal, owners.semantic_key, owners.blob_id, owners.language, owners.package,
        parent.owner_definition_semantic_key, owners.seed_owner, owners.semantic_role
 FROM owners
 CROSS JOIN main.resolution_member_owner_properties AS parent
   ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
)
SELECT owners.mount_ordinal, owners.semantic_key, owners.language, owners.package,
       owners.seed_owner, owners.owner, parent.owner_definition_semantic_key,
       scope.definition_semantic_key, owners.semantic_role
FROM owners
LEFT JOIN main.resolution_member_owner_properties AS parent
  ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
LEFT JOIN main.resolution_member_scope_properties AS scope
  ON scope.blob_id=owners.blob_id AND scope.definition_semantic_key=owners.owner AND scope.scope_kind='type_body'
"#;

// Scala caller privacy follows the producer's exact lexical scopes, including
// local functions and value initializers. The ordered template IDs seed the
// same query-owned owner-chain assembly as declaration endpoints. Import
// references use their exact source import context, including file-level imports
// with no declaration owner and sibling package blocks in one source blob.
const SCALA_REFERENCE_ENDPOINTS: &str = r#"
WITH seeds AS MATERIALIZED (
 SELECT request.mount_ordinal, request.key0 AS semantic_key, mount.blob_id,
        bridge.declaration_id,
        COALESCE(
          (SELECT prefix.prefix
           FROM main.source_imports AS import
           JOIN main.source_import_prefixes AS prefix
             ON prefix.blob_id=import.blob_id AND prefix.import_id=import.import_id
           WHERE import.blob_id=mount.blob_id
             AND import.declaration_start_byte<=site.start_byte
             AND import.declaration_end_byte>=site.end_byte
           ORDER BY import.declaration_end_byte-import.declaration_start_byte, prefix.ordinal DESC
           LIMIT 1),
          (SELECT prefix FROM main.source_scala_declaration_lexical_prefixes AS prefix
           WHERE prefix.blob_id=bridge.blob_id AND prefix.declaration_id=bridge.declaration_id
           ORDER BY ordinal DESC LIMIT 1)) AS package
 FROM temp.selected_resolution_typed_requests_1 AS request
 CROSS JOIN temp.selected_resolution_mounts AS mount
   ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language='scala'
 CROSS JOIN main.resolution_fragment_interiors AS interior
   ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
  AND interior.semantic_language=mount.semantic_language
  AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
  AND interior.publication_state='complete'
 CROSS JOIN main.resolution_semantic_sites AS reference
   ON reference.blob_id=mount.blob_id AND reference.semantic_key=request.key0 AND reference.semantic_role='reference'
 CROSS JOIN main.resolution_sites AS site ON site.blob_id=mount.blob_id AND site.site=reference.source_site
 LEFT JOIN main.resolution_semantic_sites AS owner
   ON owner.blob_id=mount.blob_id AND owner.semantic_key=NULLIF(site.owner,-1) AND owner.semantic_role='definition'
 LEFT JOIN main.source_native_declaration_bridges AS bridge
   ON bridge.blob_id=owner.blob_id AND bridge.source_site=owner.source_site
 WHERE NULLIF(site.owner,-1) IS NULL OR EXISTS (
   SELECT 1 FROM main.source_scala_declarations AS context
   WHERE context.blob_id=bridge.blob_id AND context.declaration_id=bridge.declaration_id)
), templates AS MATERIALIZED (
 SELECT seeds.mount_ordinal, seeds.semantic_key, scope.ordinal, semantic.semantic_key AS owner
 FROM seeds
 CROSS JOIN main.source_scala_declaration_lexical_scopes AS scope
   ON scope.blob_id=seeds.blob_id AND scope.declaration_id=seeds.declaration_id
 CROSS JOIN main.source_declarations AS declaration INDEXED BY source_declarations_occurrence
   ON declaration.blob_id=scope.blob_id AND declaration.occurrence_id=scope.occurrence_id
  AND declaration.name_occurrence_id IS NOT NULL
 CROSS JOIN main.source_scala_declarations AS template
   ON template.blob_id=declaration.blob_id AND template.declaration_id=declaration.declaration_id
  AND template.kind IN (1,2,3,4)
 CROSS JOIN main.source_native_declaration_bridges AS bridge
   ON bridge.blob_id=declaration.blob_id AND bridge.declaration_id=declaration.declaration_id
 CROSS JOIN main.resolution_semantic_sites AS semantic
   ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
 WHERE EXISTS (SELECT 1 FROM main.resolution_member_scope_properties AS body
   WHERE body.blob_id=semantic.blob_id AND body.definition_semantic_key=semantic.semantic_key AND body.scope_kind='type_body')
)
SELECT seeds.mount_ordinal, seeds.semantic_key, seeds.package, templates.owner
FROM seeds LEFT JOIN templates
 ON templates.mount_ordinal=seeds.mount_ordinal AND templates.semantic_key=seeds.semantic_key
ORDER BY seeds.mount_ordinal, seeds.semantic_key, templates.ordinal DESC
"#;

pub(super) fn read(
    source: &SelectedResolutionTypedSource<'_, '_>,
    semantics: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<JavaAccessEndpoint>>> {
    let mut result = std::collections::BTreeMap::new();
    for chunk in semantics.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let mut coordinates = std::collections::BTreeMap::new();
        for &semantic in chunk {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = semantic.ordinal() else {
                continue;
            };
            if source
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                != Language::Java
            {
                continue;
            }
            let Some(provenance) = source
                .authority
                .semantic_catalog_provenance(semantic, cancellation)?
            else {
                return Ok(None);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                continue;
            };
            coordinates.insert((local.mount().ordinal(), local.local_key().get()), semantic);
        }
        if coordinates.is_empty() {
            continue;
        }
        if !source
            .selection
            .replace_resolution_requests_1(coordinates.keys().copied(), cancellation)?
        {
            return Ok(None);
        }
        let rows = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(ENDPOINTS)?;
            let mut rows = statement.query([])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                let semantic = coordinates[&(ordinal, row.get::<_, i64>(1)?)];
                let root: Option<u32> = row.get(4)?;
                found.push((
                    semantic,
                    row.get::<_, Option<String>>(2)?,
                    root.map(|key| SemanticId::local(ordinal.get(), key)),
                ));
            }
            Ok(Some(found))
        })?;
        let Some(rows) = rows else { return Ok(None) };
        for (semantic, package, root) in rows {
            let endpoint = result
                .entry(semantic)
                .or_insert_with(|| JavaAccessEndpoint {
                    semantic,
                    package: package.clone(),
                    outermost_type: None,
                });
            assert_eq!(endpoint.package, package);
            if let Some(root) = root {
                assert!(
                    endpoint
                        .outermost_type
                        .is_none_or(|previous| previous == root)
                );
                endpoint.outermost_type = Some(root);
            }
        }
    }
    Ok((!cancellation.is_cancelled()).then(|| result.into_values().collect()))
}

struct JvmAccessEndpointFacts {
    language: Language,
    package: Option<String>,
    seed_owner: Option<SemanticId>,
    definition: bool,
    parents: HashMap<SemanticId, Option<SemanticId>>,
    templates: HashSet<SemanticId>,
    lexical_templates: Vec<SemanticId>,
}

pub(super) fn read_jvm(
    source: &SelectedResolutionTypedSource<'_, '_>,
    semantics: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<JvmAccessEndpoint>>> {
    let mut result = std::collections::BTreeMap::<SemanticId, JvmAccessEndpointFacts>::new();
    for chunk in semantics.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let mut coordinates = std::collections::BTreeMap::new();
        let mut has_scala = false;
        for &semantic in chunk {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = semantic.ordinal() else {
                continue;
            };
            let language = source
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language();
            if !matches!(language, Language::Java | Language::Scala) {
                continue;
            }
            let Some(provenance) = source
                .authority
                .semantic_catalog_provenance(semantic, cancellation)?
            else {
                return Ok(None);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                continue;
            };
            has_scala |= language == Language::Scala;
            coordinates.insert((local.mount().ordinal(), local.local_key().get()), semantic);
        }
        if coordinates.is_empty() {
            continue;
        }
        if !source
            .selection
            .replace_resolution_requests_1(coordinates.keys().copied(), cancellation)?
        {
            return Ok(None);
        }
        let rows = source.read_statement(cancellation, |connection| {
            let mut found = Vec::new();
            let mut statement = connection.prepare_cached(JVM_ENDPOINTS)?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                let semantic = coordinates[&(ordinal, row.get::<_, i64>(1)?)];
                let language = match row.get::<_, String>(2)?.as_str() {
                    "java" => Language::Java,
                    "scala" => Language::Scala,
                    other => panic!("JVM access query returned unexpected language {other:?}"),
                };
                let seed_owner = row
                    .get::<_, Option<u32>>(4)?
                    .map(|key| SemanticId::local(ordinal.get(), key));
                let owner = row
                    .get::<_, Option<u32>>(5)?
                    .map(|key| SemanticId::local(ordinal.get(), key));
                let parent = row
                    .get::<_, Option<u32>>(6)?
                    .map(|key| SemanticId::local(ordinal.get(), key));
                let template = row
                    .get::<_, Option<u32>>(7)?
                    .map(|key| SemanticId::local(ordinal.get(), key));
                found.push((
                    semantic,
                    language,
                    row.get::<_, Option<String>>(3)?,
                    seed_owner,
                    owner,
                    parent,
                    template,
                    row.get::<_, String>(8)? == "definition",
                ));
            }

            let mut lexical_templates = Vec::new();
            if has_scala {
                let mut statement = connection.prepare_cached(SCALA_REFERENCE_ENDPOINTS)?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                    let semantic = coordinates[&(ordinal, row.get::<_, i64>(1)?)];
                    lexical_templates.push((
                        semantic,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<u32>>(3)?
                            .map(|key| SemanticId::local(ordinal.get(), key)),
                    ));
                }
            }
            Ok(Some((found, lexical_templates)))
        })?;
        let Some((rows, lexical_templates)) = rows else {
            return Ok(None);
        };
        for (semantic, language, package, seed_owner, owner, parent, template, definition) in rows {
            let endpoint = result
                .entry(semantic)
                .or_insert_with(|| JvmAccessEndpointFacts {
                    language,
                    package: package.clone(),
                    seed_owner,
                    definition,
                    parents: HashMap::default(),
                    templates: HashSet::default(),
                    lexical_templates: Vec::new(),
                });
            assert_eq!(endpoint.language, language);
            assert_eq!(endpoint.package, package);
            assert_eq!(endpoint.seed_owner, seed_owner);
            assert_eq!(endpoint.definition, definition);
            if let Some(owner) = owner
                && let Some(previous) = endpoint.parents.insert(owner, parent)
            {
                assert_eq!(previous, parent, "one selected owner has one parent");
            }
            if let Some(template) = template {
                endpoint.templates.insert(template);
            }
        }
        for (semantic, package, template) in lexical_templates {
            let Some(endpoint) = result.get_mut(&semantic) else {
                continue;
            };
            endpoint.package = package;
            if let Some(template) = template {
                endpoint.lexical_templates.push(template);
            }
        }
    }
    let endpoints = result
        .into_iter()
        .map(|(semantic, facts)| {
            let mut enclosing_templates = Vec::new();
            let mut current = facts.seed_owner;
            if facts.definition && current == Some(semantic) && facts.templates.contains(&semantic)
            {
                current = facts.parents.get(&semantic).copied().flatten();
            }
            let mut visited = HashSet::default();
            while let Some(owner) = current {
                assert!(
                    visited.insert(owner),
                    "selected declaration owners are acyclic"
                );
                if facts.templates.contains(&owner) {
                    enclosing_templates.push(owner);
                }
                current = facts.parents.get(&owner).copied().flatten();
            }
            for template in facts.lexical_templates {
                if !enclosing_templates.contains(&template) {
                    enclosing_templates.push(template);
                }
            }
            JvmAccessEndpoint {
                semantic,
                language: facts.language,
                package: facts.package,
                outermost_type: enclosing_templates.last().copied(),
                enclosing_templates,
            }
        })
        .collect();
    Ok((!cancellation.is_cancelled()).then_some(endpoints))
}
