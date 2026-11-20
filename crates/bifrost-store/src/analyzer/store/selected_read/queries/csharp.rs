//! Recorded C# selected reads: compilation global-using inventories, selected
//! compilation labels (#13276), and per-file partial-type declaration facts
//! (#7314 M6c-S1).
use super::super::{NonEmpty, RecordedContent, SelectedDependency};
use crate::analyzer::Language;
use crate::analyzer::store::resolution_operation::imports::{ImportRoute, read_route_at};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::gitblob::ParseVariant;
use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
    FactSubject, LookupQuestion, WorkspaceFactFamily,
};
use rusqlite::params;

/// One compilation, named the way every C# unit names it: the project path (or
/// the reserved loose key) qualified by its target framework. Compilation ids
/// are database rows and never name a compilation across workspaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CSharpCompilationLabel {
    pub compilation_id: i64,
    pub label: Box<str>,
}

/// The label of a compilation: its project path, or the reserved key of a
/// loose compilation (a NUL cannot occur in a workspace path), qualified by its
/// target framework.
pub fn compilation_label(project_path: Option<&str>, target_framework: Option<&str>) -> String {
    crate::analyzer::store::csharp_compilation::framework_qualified_label(
        project_path.unwrap_or("\0loose").to_owned(),
        target_framework,
    )
}

/// Part 0 of the inventory statement: coverage. Part 1: one row per installed
/// global-using site of the compilation's members.
pub const SELECTED_GLOBAL_USING_INVENTORY: &str = concat!(
    "SELECT 0,v.membership_complete,v.publications_expected,v.publications_installed,json(v.reasons),
 NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL
 FROM temp.selected_csharp_compilation_using_coverage v
 JOIN main.csharp_compilations c ON c.compilation_id=v.compilation_id
 JOIN main.csharp_compilation_sets s ON s.set_id=c.set_id AND s.derivation_identity=?2
 WHERE v.compilation_id=?1
 UNION ALL
 SELECT 1,NULL,NULL,NULL,NULL,e.rel_path,e.blob_id,e.import_site,s.local_name,m.blob_id,b.blob_oid,b.parse_variant,",
    // The `read_route_at` columns. Both child tables are read in primary-key
    // order, which the subselect ORDER BYs state without a temp b-tree.
    "route.import_site,route.root_scope,route.anchor,route.position,route.kind,route.bound_name,
 (SELECT json_group_array(segment) FROM (SELECT segment FROM resolution_root_import_segments AS segment
   WHERE segment.blob_id=route.blob_id AND segment.import_site=route.import_site ORDER BY segment.position)),
 (SELECT json_group_array(json_array(namespace,name,target_kind,target_reference,target_name)) FROM
   (SELECT demand.namespace,demand.name,demand.target_kind,demand.target_reference,demand.target_name
    FROM resolution_root_import_demands AS demand
    WHERE demand.blob_id=route.blob_id AND demand.import_site=route.import_site ORDER BY demand.namespace,demand.name))",
    "
 FROM temp.selected_csharp_global_using_extent e
 LEFT JOIN main.blobs b ON b.id=e.blob_id
 LEFT JOIN main.resolution_import_selectors s ON s.blob_id=e.blob_id AND s.site=e.import_site
 LEFT JOIN temp.selected_resolution_mounts m
  ON m.blob_id=e.blob_id AND m.semantic_language='csharp' AND m.persisted_relative_path=e.rel_path
 LEFT JOIN main.resolution_root_imports route ON route.blob_id=e.blob_id AND route.import_site=e.import_site
 WHERE e.compilation_id=?1"
);

/// The selected set's compilations, for naming one by label on a head that
/// holds no compilation id.
pub const SELECTED_COMPILATION_LABELS: &str =
    "SELECT compilation.compilation_id, compilation.project_path, compilation.target_framework
    FROM csharp_compilations AS compilation
    JOIN csharp_compilation_selections AS selected ON selected.set_id = compilation.set_id
    JOIN temp.selected_workspace_revisions AS revision
      ON revision.workspace_id = selected.workspace_id AND revision.lang = selected.lang
     AND revision.generation = selected.generation AND revision.revision = selected.revision
    WHERE selected.lang = 'csharp'";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GlobalUsingParams {
    pub compilation_id: i64,
    /// The compilation's label, the subject of the recorded fact.
    pub label: Box<str>,
}

#[derive(Clone, Debug)]
pub struct GlobalUsingCoverage {
    pub membership_complete: bool,
    pub publications_expected: i64,
    pub publications_installed: i64,
    /// Members whose directive enumeration is incomplete, sorted.
    pub enumeration_gaps: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GlobalUsingSite {
    pub path: String,
    pub blob: i64,
    pub site: u32,
    pub alias: Option<String>,
    /// Whether the selection mounts this very blob at `path`.
    pub mount_agrees: bool,
    /// The published content identity of `path`'s blob: the declaring file's
    /// own fragment is read later by name lookups, so its content is part of
    /// the fact. Only files that carry a global using are named here.
    pub content: Option<(String, ParseVariant)>,
    pub route: Option<ImportRoute>,
}

#[derive(Clone, Debug, Default)]
pub struct GlobalUsingInventory {
    pub coverage: Option<GlobalUsingCoverage>,
    pub sites: Vec<GlobalUsingSite>,
}

/// One type declaration of one selected file, by its mount-local semantic key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CSharpDeclarationKey {
    pub content: RecordedContent,
    pub definition: u32,
}

/// Nested-type declarations named `name` directly inside any of `owners`
/// (mount-local semantic keys of enclosing type declarations of the file).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CSharpNestedTypeKey {
    pub content: RecordedContent,
    pub owners: Box<[u32]>,
    pub name: Box<str>,
}

/// One namespace scope of one selected file, by its mount-local node key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CSharpNamespaceScopeKey {
    pub content: RecordedContent,
    pub scope: u32,
}

/// What a type declaration says about itself. `partial` is None when the file
/// lacks the modifier row, which is distinct from a proven non-partial type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSharpDeclarationFacts {
    pub partial: Option<bool>,
    /// The enclosing type declaration and this declaration's member name when
    /// it is a nested type, None for a namespace-level declaration.
    pub nested_in: Option<(u32, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSharpNestedTypeRow {
    pub definition: u32,
    pub partial: Option<bool>,
}

fn file_dependency(content: &RecordedContent) -> NonEmpty<SelectedDependency> {
    let mount = &content.mount;
    NonEmpty::one(SelectedDependency::Path {
        language: mount.language,
        rel_path: mount.path.clone(),
        selected: Some((mount.oid, mount.variant)),
    })
}

fn content_bytes(content: &RecordedContent) -> usize {
    std::mem::size_of::<RecordedContent>() + content.mount.path.len() + content.receipt_bytes
}

fn decode_inventory(
    statement: &mut rusqlite::Statement<'_>,
    params: &GlobalUsingParams,
) -> Result<GlobalUsingInventory, super::super::SelectedReadError> {
    let mut inventory = GlobalUsingInventory::default();
    let mut rows = statement.query(params![
        params.compilation_id,
        crate::analyzer::store::csharp_compilation::derivation_identity().as_slice()
    ])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, i64>(0)? == 0 {
            let reasons: Vec<serde_json::Value> = serde_json::from_str(&row.get::<_, String>(4)?)
                .map_err(|error| {
                crate::analyzer::store::StoreError::corrupt(format!(
                    "invalid global-using coverage reasons: {error}"
                ))
            })?;
            let mut enumeration_gaps = Vec::new();
            for reason in &reasons {
                if reason["kind"] != "source_enumeration" {
                    continue;
                }
                let paths = reason["paths"].as_array().ok_or_else(|| {
                    crate::analyzer::store::StoreError::corrupt(
                        "source enumeration reason lacks its paths",
                    )
                })?;
                for path in paths {
                    enumeration_gaps.push(
                        path.as_str()
                            .ok_or_else(|| {
                                crate::analyzer::store::StoreError::corrupt(
                                    "source enumeration path is not text",
                                )
                            })?
                            .to_owned(),
                    );
                }
            }
            enumeration_gaps.sort_unstable();
            enumeration_gaps.dedup();
            inventory.coverage = Some(GlobalUsingCoverage {
                membership_complete: row.get(1)?,
                publications_expected: row.get(2)?,
                publications_installed: row.get(3)?,
                enumeration_gaps,
            });
        } else {
            let route = match row.get::<_, Option<u32>>(12)? {
                Some(_) => Some(read_route_at(row, 12)?),
                None => None,
            };
            inventory.sites.push(GlobalUsingSite {
                path: row.get(5)?,
                blob: row.get(6)?,
                site: row.get(7)?,
                alias: row.get(8)?,
                mount_agrees: row.get::<_, Option<i64>>(9)?.is_some(),
                content: row.get::<_, Option<String>>(10)?.zip(row.get(11)?),
                route,
            });
        }
    }
    Ok(inventory)
}

/// The digest recorded as `Lookup WorkspaceFact CSharpCompilationGlobalUsings`
/// and recomputed on a head by the same call. It folds exactly what a global
/// using consumer can observe about one compilation: whether membership is
/// complete, which members' directive enumeration is incomplete, whether every
/// publication is installed, and each site's file, mount agreement, alias and
/// route content, plus the content identity of each file that carries a global
/// using (name lookups through its fragment read that file's rows). Database
/// blob ids, site ordinals, member counts and the content of every file that
/// carries no global using stay out, so an edit elsewhere leaves it unchanged.
pub fn global_using_inventory_digest(inventory: &GlobalUsingInventory) -> StableDigest {
    let mut hash = CanonicalHasher::new(b"bifrost-csharp-compilation-global-usings:v1");
    match &inventory.coverage {
        None => hash.field("coverage", b"missing"),
        Some(coverage) => {
            hash.field("coverage", b"present");
            hash.field("membership_complete", &[coverage.membership_complete as u8]);
            hash.field(
                "publications_match",
                &[(coverage.publications_expected == coverage.publications_installed) as u8],
            );
            for path in &coverage.enumeration_gaps {
                hash.field("enumeration_gap", path.as_bytes());
            }
        }
    }
    let mut sites: Vec<String> = inventory
        .sites
        .iter()
        .map(|site| {
            let mount = if site.mount_agrees {
                "agrees"
            } else {
                "disagrees"
            };
            match &site.route {
                None => format!(
                    "{:?}",
                    (&site.path, &site.alias, mount, &site.content, "no route")
                ),
                Some(route) => format!(
                    "{:?}",
                    (
                        &site.path,
                        &site.alias,
                        mount,
                        &site.content,
                        &route.kind,
                        &route.bound_name,
                        &route.segments,
                        &route.demands
                    )
                ),
            }
        })
        .collect();
    sites.sort_unstable();
    for site in &sites {
        hash.field("site", site.as_bytes());
    }
    StableDigest::from_array(hash.finish())
}

/// The question the digest answers.
pub fn global_using_question(label: &str) -> LookupQuestion {
    LookupQuestion::WorkspaceFact {
        family: WorkspaceFactFamily::CSharpCompilationGlobalUsings,
        language: Language::CSharp,
        subject: FactSubject::Named { name: label.into() },
    }
}

selected_queries! {
    selection CSharpGlobalUsingInventory {
        params: GlobalUsingParams, answer: GlobalUsingInventory,
        sql: SELECTED_GLOBAL_USING_INVENTORY,
        read: decode_inventory,
        bytes: |answer: &GlobalUsingInventory| std::mem::size_of::<GlobalUsingInventory>()
            + answer.sites.iter().map(|site| std::mem::size_of::<GlobalUsingSite>() + site.path.len()).sum::<usize>(),
        params_bytes: |params: &GlobalUsingParams| std::mem::size_of::<GlobalUsingParams>() + params.label.len(),
        contract: |params: &GlobalUsingParams, answer: &GlobalUsingInventory| NonEmpty::one(
            SelectedDependency::WorkspaceFactDigest {
                question: Box::new(global_using_question(&params.label)),
                digest: global_using_inventory_digest(answer),
            })
    }
    // Head-side recompute only: the labelled compilations of the selected set.
    selection CSharpCompilationLabels {
        params: (), answer: Vec<CSharpCompilationLabel>,
        sql: SELECTED_COMPILATION_LABELS,
        read: |statement: &mut rusqlite::Statement<'_>, _: &()| {
            let mut rows = statement.query([])?;
            let mut labels = Vec::new();
            while let Some(row) = rows.next()? {
                let project_path: Option<String> = row.get(1)?;
                labels.push(CSharpCompilationLabel {
                    compilation_id: row.get(0)?,
                    label: compilation_label(
                        project_path.as_deref(),
                        row.get::<_, Option<String>>(2)?.as_deref(),
                    )
                    .into(),
                });
            }
            Ok(labels)
        },
        bytes: |answer: &Vec<CSharpCompilationLabel>| answer.iter().map(|label| std::mem::size_of::<CSharpCompilationLabel>() + label.label.len()).sum::<usize>(),
        params_bytes: |_: &()| 0,
        contract: |_: &(), _: &Vec<CSharpCompilationLabel>| NonEmpty::one(
            SelectedDependency::Scope { languages: vec![Language::CSharp].into_boxed_slice() })
    }
    selection CSharpDeclarationFactsRead {
        params: CSharpDeclarationKey, answer: CSharpDeclarationFacts,
        sql: "SELECT (SELECT modifier.partial FROM main.resolution_declaration_modifiers modifier WHERE modifier.blob_id=?1 AND modifier.definition=?2), owner.owner_definition_semantic_key, owner.member_name FROM (SELECT 1) LEFT JOIN main.resolution_member_owner_properties owner ON owner.blob_id=?1 AND owner.definition_semantic_key=?2 AND owner.member_kind='nested_type'",
        read: |statement: &mut rusqlite::Statement<'_>, params: &CSharpDeclarationKey| Ok(statement.query_row(params![params.content.mount.blob_id, params.definition], |row| {
            let partial: Option<i64> = row.get(0)?;
            let owner: Option<u32> = row.get(1)?;
            let name: Option<String> = row.get(2)?;
            Ok(CSharpDeclarationFacts { partial: partial.map(|value| value != 0), nested_in: owner.zip(name) })
        })?),
        bytes: |answer: &CSharpDeclarationFacts| std::mem::size_of::<CSharpDeclarationFacts>() + answer.nested_in.as_ref().map_or(0, |(_, name)| name.len()),
        params_bytes: |params: &CSharpDeclarationKey| std::mem::size_of::<CSharpDeclarationKey>() + content_bytes(&params.content),
        contract: |params: &CSharpDeclarationKey, _: &CSharpDeclarationFacts| file_dependency(&params.content)
    }
    selection CSharpNestedTypeRead {
        params: CSharpNestedTypeKey, answer: Vec<CSharpNestedTypeRow>,
        sql: "SELECT owner.definition_semantic_key, modifier.partial FROM json_each(?2) requested CROSS JOIN main.resolution_member_owner_properties owner ON owner.blob_id=?1 AND owner.owner_definition_semantic_key=requested.value AND owner.member_kind='nested_type' AND owner.member_name=?3 LEFT JOIN main.resolution_declaration_modifiers modifier ON modifier.blob_id=owner.blob_id AND modifier.definition=owner.definition_semantic_key ORDER BY owner.definition_semantic_key",
        read: |statement: &mut rusqlite::Statement<'_>, params: &CSharpNestedTypeKey| {
            let owners = serde_json::to_string(&params.owners).expect("owner keys serialize");
            let mut rows = statement.query(params![params.content.mount.blob_id, owners, params.name.as_ref()])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let partial: Option<i64> = row.get(1)?;
                result.push(CSharpNestedTypeRow { definition: row.get(0)?, partial: partial.map(|value| value != 0) });
            }
            Ok(result)
        },
        bytes: |answer: &Vec<CSharpNestedTypeRow>| answer.capacity() * std::mem::size_of::<CSharpNestedTypeRow>(),
        params_bytes: |params: &CSharpNestedTypeKey| std::mem::size_of::<CSharpNestedTypeKey>() + content_bytes(&params.content) + params.owners.len() * std::mem::size_of::<u32>() + params.name.len(),
        contract: |params: &CSharpNestedTypeKey, _: &Vec<CSharpNestedTypeRow>| file_dependency(&params.content)
    }
    selection CSharpNamespaceRouteRead {
        params: CSharpNamespaceScopeKey, answer: Option<Vec<String>>,
        sql: "SELECT s.spelling FROM main.resolution_package_routes r LEFT JOIN main.resolution_package_route_segments s ON s.blob_id=r.blob_id AND s.package_scope_node_key=r.package_scope_node_key WHERE r.blob_id=?1 AND r.package_scope_node_key=?2 ORDER BY s.ordinal",
        read: |statement: &mut rusqlite::Statement<'_>, params: &CSharpNamespaceScopeKey| {
            let mut rows = statement.query(params![params.content.mount.blob_id, params.scope])?;
            let mut route = None;
            while let Some(row) = rows.next()? {
                let segments: &mut Vec<String> = route.get_or_insert_with(Vec::new);
                if let Some(spelling) = row.get::<_, Option<String>>(0)? {
                    segments.push(spelling);
                }
            }
            Ok(route)
        },
        bytes: |answer: &Option<Vec<String>>| answer.as_ref().map_or(0, |route| route.iter().map(|segment| segment.len() + std::mem::size_of::<String>()).sum()),
        params_bytes: |params: &CSharpNamespaceScopeKey| std::mem::size_of::<CSharpNamespaceScopeKey>() + content_bytes(&params.content),
        contract: |params: &CSharpNamespaceScopeKey, _: &Option<Vec<String>>| file_dependency(&params.content)
    }
}
