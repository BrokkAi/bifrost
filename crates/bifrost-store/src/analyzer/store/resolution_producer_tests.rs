#[cfg(any(test, feature = "test-support"))]
use self::producer_test_support::*;
#[cfg(test)]
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

#[cfg(test)]
use brokk_bifrost_test_macros::hardwon;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use git2::Oid;

#[cfg(any(test, feature = "test-support"))]
use rusqlite::params;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use tree_sitter::Parser;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::CancellationToken;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::BindingFragmentId;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::DeferredMemberOwnerLookupName;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::LoweredCandidateDirection;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::LoweringCoverageFrontier;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::LoweringGapOrigin;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::PreloadedFactResolutionService;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::SelectedTypedFactSource;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::SemanticId;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::TypedFactPageVisitor;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::TypedFactRequest;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution::TypedFactRelation;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_prepare::ResolutionInteriorPreparation;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_prepare::prepare_resolution_bundle_with_unit_keys;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::file_state::FileState;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::CodeUnit;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::Language;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::ProjectFile;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::hash::HashMap;

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use super::test_blob_oid as oid;

use super::*;

#[cfg(test)]
fn parsed_unit_keys(parsed: &ParsedFile) -> HashMap<CodeUnit, i64> {
    parsed
        .declarations()
        .iter()
        .enumerate()
        .map(|(index, unit)| {
            (
                unit.clone(),
                i64::try_from(index).expect("parsed fixture unit count fits i64"),
            )
        })
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_projection(state: &Arc<FileState>) -> Arc<FileState> {
    let mut projection = state.as_ref().clone();
    projection.source.clear();
    projection.additional_projections.clear();
    let mut primary = state.as_ref().clone();
    primary.additional_projections = vec![(PROJECTION, Arc::new(projection))];
    Arc::new(primary)
}

#[cfg(test)]
fn assert_plan_search(plan: &[String], alias: &str, index: &str) {
    assert!(
        plan.iter().any(|detail| {
            detail.contains(&format!("SEARCH {alias} ")) && detail.contains(index)
        }),
        "complete-analysis query must seek {alias} through {index}: {plan:#?}"
    );
}

#[cfg(test)]
fn assert_bounded_complete_analysis_plan(plan: &[String]) {
    assert!(
        plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
        "complete-analysis queries must not depend on automatic indexes: {plan:#?}"
    );
    for detail in plan.iter().filter(|detail| detail.contains("SCAN ")) {
        let scanned_alias = detail
            .split_once("SCAN ")
            .and_then(|(_, tail)| tail.split_ascii_whitespace().next())
            .expect("SCAN plan detail names its table alias");
        assert!(
            matches!(scanned_alias, "requested" | "projection" | "owner"),
            "only bounded TEMP request carriers may be scanned: {plan:#?}"
        );
    }
    for detail in plan
        .iter()
        .filter(|detail| detail.contains("USE TEMP B-TREE"))
    {
        assert!(
            detail.contains("USE TEMP B-TREE FOR ORDER BY"),
            "TEMP storage is allowed only for request-order restoration: {plan:#?}"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn persist_one(store: &AnalyzerStore, prepared: PreparedParsedBlob) -> PersistBatchStats {
    let (outcomes, stats) =
        store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
    stats
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn payload_cost(store: &AnalyzerStore, oid: Oid, lang: &str) -> usize {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        conn.query_row(
            "SELECT costs.payload_bytes
             FROM blobs
             JOIN blob_payload_costs AS costs ON costs.blob_id = blobs.id
             WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2",
            params![oid, lang],
            |row| row.get::<_, usize>(0),
        )
        .expect("persisted blob payload cost")
    })
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rewrite_payload_cost(store: &AnalyzerStore, oid: Oid, lang: &str, value: Option<usize>) {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| match value {
        Some(value) => conn
            .execute(
                "UPDATE blob_payload_costs
                 SET payload_bytes = ?3
                 WHERE blob_id = (
                   SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2
                 )",
                params![oid, lang, value],
            )
            .expect("corrupt persisted payload cost"),
        None => conn
            .execute(
                "DELETE FROM blob_payload_costs
                 WHERE blob_id = (
                   SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2
                 )",
                params![oid, lang],
            )
            .expect("delete persisted payload cost"),
    });
}

#[cfg(test)]
#[test]
fn manifest_count_columns_match_the_persisted_schema_by_name() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let mut schema_columns = store.conn.execute(|conn| {
        conn.prepare(
            "SELECT name
             FROM pragma_table_info('resolution_fragment_interiors')
             WHERE name LIKE 'expected_%_count'
             ORDER BY cid",
        )
        .expect("prepare resolution manifest schema descriptor")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query resolution manifest schema descriptor")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("read resolution manifest schema descriptor")
    });
    let mut declared_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .map(|column| (*column).to_owned())
        .collect::<Vec<_>>();
    // Migration-added columns may occupy different physical positions. All
    // production queries bind these columns by name, not their schema cid.
    schema_columns.sort_unstable();
    declared_columns.sort_unstable();
    assert_eq!(schema_columns, declared_columns);
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn persisted_physical_logical_rows(store: &AnalyzerStore, keys: &[(Oid, &str)]) -> Vec<usize> {
    let keys = keys
        .iter()
        .map(|(oid, language)| (oid.to_string(), (*language).to_owned()))
        .collect::<Vec<_>>();
    store.conn.execute(move |conn| {
        let mut statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .expect("prepare physical cascade-row recomputation");
        keys.iter()
            .map(|(oid, language)| {
                let cascade =
                    persisted_blob_mutation_cost_fallback_statement(&mut statement, oid, language)
                        .expect("recompute persisted cascade rows");
                let payload_cost_rows = conn
                    .query_row(
                        "SELECT COUNT(*)
                         FROM blob_payload_costs AS costs
                         JOIN blobs AS blob ON blob.id = costs.blob_id
                         WHERE blob.blob_oid = ?1 AND blob.lang = ?2",
                        params![oid, language],
                        |row| row.get::<_, usize>(0),
                    )
                    .expect("count the persisted payload-cost row");
                assert_eq!(payload_cost_rows, 1);
                cascade.logical_rows
            })
            .collect()
    })
}

#[cfg(test)]
/// A relation's rows are exactly the shared identities its read answers.
///
/// This is the contract the whole family rests on: a typed read opens the
/// blobs its relation names and no others, so a blob whose interior would have
/// answered and has no row is a wrong answer, and a blob with a row that
/// answers nothing is an interior produced for nothing. The oracle is the
/// interior itself. For each fixture blob, the persisted rows are compared
/// against what `PreloadedFactResolutionService` -- the same index the mounted
/// read consults, built from the same lowered fragment -- returns when it is
/// asked that relation's question about each shared identity in the blob's
/// catalog.
///
/// A fragment-local key never reaches a relation: `semantic_coordinates`
/// resolves it through the rebaser to the one mount that owns it. That is why
/// the sweep is over the shared slice of the catalog and why most relations
/// carry no rows at all.
#[test]
#[hardwon("dfb60686e6e4: persisted typed-fact membership drifted from the reader answer set")]
fn every_typed_relation_names_exactly_the_shared_identities_its_read_answers() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    const RICH_SOURCE: &str = concat!(
        "pub mod inner {\n",
        "    pub struct Thing {\n        pub field: u32,\n    }\n",
        "    impl Thing {\n",
        "        pub fn make(value: u32) -> Self {\n            Self { field: value }\n        }\n",
        "        pub fn read(&self) -> u32 {\n            self.field\n        }\n",
        "    }\n",
        "    pub trait Read {\n        fn read(&self) -> u32;\n    }\n",
        "    impl Read for Thing {\n        fn read(&self) -> u32 {\n            self.field\n        }\n    }\n",
        "}\n",
        "use inner::{Read, Thing};\n",
        "type ItemAlias<T> = Option<T>;\n",
        "pub fn use_it(thing: &Thing, absent: Absent) -> u32 {\n",
        "    Read::read(thing) + Thing::make(1).read() + absent.shared_member()\n",
        "}\n",
        "pub fn use_alias(value: ItemAlias<Thing>) -> ItemAlias<Thing> { value }\n",
    );
    let mut sources = vec![
        ("src/rich.rs".to_owned(), RICH_SOURCE.to_owned()),
        (
            "src/route_holder.rs".to_owned(),
            ROUTE_ISOLATING_HOLDER.to_owned(),
        ),
        (
            "src/member_holder.rs".to_owned(),
            MEMBER_ISOLATING_HOLDER.to_owned(),
        ),
    ];
    for index in 0..4usize {
        sources.push((
            format!("src/declaring_{index:04}.rs"),
            format!(
                "pub struct S{index:04};
impl S{index:04} {{ pub fn shared_route(&self) -> usize {{ {index} }} }}
"
            ),
        ));
        sources.push((
            format!("src/calling_{index:04}.rs"),
            format!(
                "pub fn scale_{index:04}(value: Absent{index:04}) -> usize {{ value.shared_member() }}
"
            ),
        ));
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure the Rust parser");
    let mut checked = 0usize;
    let mut with_rows = std::collections::BTreeSet::new();
    for (path, source) in &sources {
        let file = ProjectFile::new(
            fixture_project_root("typed-relation-oracle-does-not-touch-disk"),
            path,
        );
        let tree = parser
            .parse(source, None)
            .expect("parse the oracle fixture");
        let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
        let unit_keys = parsed_unit_keys(&parsed);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(path.as_bytes()),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &parsed.resolution_facts,
        );
        let ResolutionInteriorPreparation::Prepared(prepared) =
            prepare_resolution_bundle_with_unit_keys(
                &lowered,
                Some(&unit_keys),
                &CancellationToken::default(),
            )
        else {
            panic!("uncancelled oracle preparation must finish for {path}");
        };
        let recorded = prepared
            .typed_fact_lookups()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let shared = lowered
            .identities()
            .semantics()
            .iter()
            .filter_map(|(semantic, identity)| {
                identity
                    .shared_name()
                    .map(|name| (*semantic, lowered.identities().shared_name_digest(name)))
            })
            .collect::<Vec<_>>();
        assert!(
            !shared.is_empty(),
            "{path} must carry shared identities for the sweep to mean anything"
        );
        let (lexical, typed, _) = lowered.into_parts();
        let service = PreloadedFactResolutionService::from_lowered_fragments([lexical], [typed]);
        let cancellation = CancellationToken::default();
        let mut disagreements = Vec::new();
        for relation in TypedFactRelation::ALL {
            for (semantic, digest) in &shared {
                let answered =
                    typed_relation_answers(&service, *relation, *semantic, &cancellation);
                let written = recorded.contains(&(relation.code(), *digest));
                if answered != written {
                    disagreements.push((relation.label(), *semantic, answered, written));
                }
                if written {
                    with_rows.insert(relation.label());
                }
                checked += 1;
            }
        }
        assert!(
            disagreements.is_empty(),
            "in {path} a relation's rows must be exactly the shared identities its \
             read answers (relation, identity, interior answers, row written): \
             {disagreements:?}"
        );
    }
    eprintln!(
        "{checked} (relation, shared identity) pairs checked over {} blobs; relations with \
         rows: {with_rows:?}",
        sources.len()
    );
    assert!(
        checked > 0 && !with_rows.is_empty(),
        "the oracle fixtures must exercise at least one relation"
    );
}

#[cfg(test)]
/// Does this blob's interior answer this relation's question about this
/// identity?
///
/// One arm per relation, over the same reads `resolution_typed.rs` composes
/// membership for, so a relation added there without a writer loop fails to
/// compile here.
fn typed_relation_answers(
    service: &PreloadedFactResolutionService,
    relation: TypedFactRelation,
    semantic: SemanticId,
    cancellation: &CancellationToken,
) -> bool {
    macro_rules! answered {
        ($method:ident, $request:expr) => {{
            let mut rows = 0usize;
            let mut sink = |page: &[_]| {
                rows += page.len();
                Ok(true)
            };
            let mut visitor = TypedFactPageVisitor::new(&mut sink);
            let request = [$request];
            // A Rust reference context read reports a missing row as a store
            // error rather than an empty page, which is the same answer for
            // this question: the interior holds nothing under the identity.
            let outcome =
                service.$method(TypedFactRequest::new(&request), cancellation, &mut visitor);
            outcome.is_ok() && rows > 0
        }};
    }
    match relation {
        TypedFactRelation::EmbeddedTypeLookup
        | TypedFactRelation::InterfaceMethodLookup
        | TypedFactRelation::SupertypeNameLookup => false,
        TypedFactRelation::RustReferenceContext => {
            answered!(visit_rust_reference_context_pages, semantic)
        }
        TypedFactRelation::RustDeclarationAuthority => {
            answered!(visit_rust_declaration_authority_pages, semantic)
        }
        TypedFactRelation::TypedFrontierSlot => answered!(visit_typed_frontier_pages, semantic),
        TypedFactRelation::TypeIdentityObservationReference => {
            answered!(
                visit_type_identity_observation_pages_for_references,
                semantic
            )
        }
        TypedFactRelation::TypeFrontierCompletionFrontier => {
            answered!(visit_type_frontier_completion_pages, semantic)
        }
        TypedFactRelation::TypeTransferSourceSlot => {
            answered!(visit_type_transfer_pages_from_sources, semantic)
        }
        TypedFactRelation::TypeTransferTargetSlot => {
            answered!(visit_type_transfer_pages_to_targets, semantic)
        }
        TypedFactRelation::TypeProductionOutput => {
            answered!(visit_type_production_pages_for_outputs, semantic)
        }
        TypedFactRelation::TypeComponentContainer => {
            answered!(visit_type_component_pages_for_containers, semantic)
        }
        TypedFactRelation::DeclaredTypeArgumentOwner => {
            answered!(visit_declared_type_argument_pages_for_owners, semantic)
        }
        TypedFactRelation::TypeArgumentApplication => {
            answered!(visit_type_argument_pages_for_applications, semantic)
        }
        TypedFactRelation::GenericTypeAliasDefinition => {
            answered!(
                visit_generic_type_alias_parameter_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::GenericFormalOwner => {
            answered!(visit_generic_formal_pages_for_owners, semantic)
        }

        TypedFactRelation::GenericFormalDefaultOwner => {
            answered!(visit_generic_formal_default_pages_for_owners, semantic)
        }
        TypedFactRelation::UnderlyingTypeDefinition => {
            answered!(visit_underlying_type_pages_for_definitions, semantic)
        }
        TypedFactRelation::IntrinsicSeedSlot => {
            answered!(visit_intrinsic_seed_pages_for_slots, semantic)
        }
        TypedFactRelation::IntrinsicSeedTypeIdentity => {
            answered!(visit_intrinsic_seed_pages_for_type_identities, semantic)
        }
        TypedFactRelation::BindingProjectionReference => {
            answered!(visit_binding_projection_pages_for_references, semantic)
        }
        TypedFactRelation::BindingProjectionOutputSlot => {
            answered!(visit_binding_projection_pages_for_outputs, semantic)
        }
        TypedFactRelation::QualifiedRouteReference => {
            answered!(visit_qualified_route_pages_for_references, semantic)
        }
        TypedFactRelation::QualifiedRouteQualifierSlot => {
            answered!(visit_qualified_route_pages_for_qualifier_slots, semantic)
        }
        // The completion-lookup index and the slot-lookup index hold the same
        // lookups, which is why one relation serves both reads and the route
        // inventory; probing either proves the row set.
        TypedFactRelation::QualifiedRouteLookup => {
            answered!(visit_qualified_route_pages_for_lookups, semantic)
        }
        TypedFactRelation::QualifiedRouteGapReason => {
            answered!(visit_qualified_route_pages_for_gap_reasons, semantic)
        }
        TypedFactRelation::DeclarationTypeDefinition => {
            answered!(visit_declaration_type_pages_for_definitions, semantic)
        }
        TypedFactRelation::DeclarationTypeSlot => {
            answered!(visit_declaration_type_pages_for_slots, semantic)
        }
        TypedFactRelation::DeclarationVisibilityDefinition => {
            answered!(visit_declaration_visibility_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberScopeDefinition => {
            answered!(visit_member_scope_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberOwnerDefinition => {
            answered!(visit_member_owner_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberOwnerOwnerDefinition => {
            answered!(visit_member_owner_pages_for_owners, semantic)
        }
        TypedFactRelation::DeferredMemberOwnerDefinition => {
            answered!(visit_deferred_member_owner_pages_for_definitions, semantic)
        }
        TypedFactRelation::DeferredMemberOwnerLookup => answered!(
            visit_deferred_member_owner_pages_for_lookup_names,
            DeferredMemberOwnerLookupName::new(semantic)
        ),
        TypedFactRelation::ConstructionRequirementDefinition => {
            answered!(
                visit_construction_requirement_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::SupertypeDefinition => {
            answered!(visit_supertype_pages_for_definitions, semantic)
        }
        TypedFactRelation::SupertypeReference => {
            answered!(visit_supertype_pages_for_references, semantic)
        }
        TypedFactRelation::SupertypeFrontier => {
            answered!(visit_supertype_pages_for_frontiers, semantic)
        }
        TypedFactRelation::DefinitionPropertyGapReason => {
            answered!(visit_definition_property_gap_pages_for_reasons, semantic)
        }
        TypedFactRelation::DefinitionPropertyGapDefinition => {
            answered!(
                visit_definition_property_gap_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::CallApplicabilityCalleeReference => {
            answered!(
                visit_call_applicability_pages_for_callee_references,
                semantic
            )
        }
        TypedFactRelation::CallApplicabilityGapReason => {
            answered!(visit_call_applicability_pages_for_gap_reasons, semantic)
        }
        TypedFactRelation::CallableSignatureDefinition => {
            answered!(visit_callable_signature_pages_for_definitions, semantic)
        }
        TypedFactRelation::GapReasonProvenanceReason => {
            answered!(visit_gap_reason_provenance_pages_for_reasons, semantic)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_publication_tests.rs"]
#[doc(hidden)]
pub mod selected_publication;

// This oracle discovers the persisted variable-width columns from SQLite's
// schema, independently of the production manifest family/column inventory.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn measured_resolution_payload(store: &AnalyzerStore, oid: Oid, lang: &str) -> usize {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        let blob_id: i64 = conn
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid=?1 AND lang=?2",
                params![oid, lang],
                |row| row.get(0),
            )
            .unwrap();
        let names = conn
            .prepare(
                "SELECT name FROM sqlite_schema
            WHERE (type='table' AND name GLOB 'resolution_*')
               OR name='resolution_declaration_visibility_properties'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut bytes = 0usize;
        for name in names {
            let columns = conn
                .prepare("SELECT name,type FROM pragma_table_info(?1)")
                .unwrap()
                .query_map([&name], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            if !columns.iter().any(|(column, _)| column == "blob_id") {
                continue;
            }
            for (column, kind) in columns {
                if !matches!(kind.as_str(), "TEXT" | "BLOB") || column == "publication_state" {
                    continue;
                }
                let sql = format!(
                    "SELECT COALESCE(SUM(length(CAST(\"{}\" AS BLOB))),0)
                    FROM \"{}\" WHERE blob_id=?1",
                    column.replace('"', "\"\""),
                    name.replace('"', "\"\"")
                );
                bytes += conn
                    .query_row(&sql, [blob_id], |row| row.get::<_, usize>(0))
                    .unwrap();
            }
        }
        bytes
    })
}

#[cfg(test)]
#[test]
fn rust_first_tranche_survives_common_lowering_and_bundle_preparation() {
    let source = "use engine::Thing as LocalThing;\npub fn callee(value: i32) -> i32 { value }\nfn caller(input: i32) -> i32 { let local = input; callee(local) }\n";
    let file = ProjectFile::new(
        fixture_project_root("selected-rust-context-does-not-touch-disk"),
        "lib.rs",
    );
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    let tree = parser.parse(source, None).expect("parse Rust fixture");
    let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
    let unit_keys = parsed_unit_keys(&parsed);
    let facts = parsed.resolution_facts;

    assert!(!facts.identifiers.is_empty());
    assert!(!facts.binders.is_empty());
    assert_eq!(facts.root_imports.len(), 1);
    // Root exports retain every named declaration as a candidate endpoint;
    // terminal visibility is applied by the selected resolver.  The fixture
    // has both the public callee and the private caller.
    assert_eq!(facts.root_exports.len(), 2);
    assert_eq!(facts.calls.len(), 1);
    // `callee(local)` writes one actual; `callee` and `caller` each declare
    // one parameter.
    assert_eq!(facts.call_arguments.len(), 1);
    assert_eq!(facts.callable_parameters.len(), 2);
    assert!(
        facts
            .type_slots
            .iter()
            .any(|slot| slot.role == ResolutionTypeSlotRole::CallResult)
    );
    let mut point_gaps = facts
        .gaps
        .iter()
        .map(|gap| {
            let site = facts.sites[gap.site.index()];
            (
                &source[site.start_byte..site.end_byte],
                gap.kind,
                site.start_byte,
                site.end_byte,
            )
        })
        .collect::<Vec<_>>();
    point_gaps.sort_by_key(|(_, kind, start_byte, end_byte)| (*start_byte, *end_byte, *kind));
    assert_eq!(
        point_gaps
            .iter()
            .map(|(spelling, kind, _, _)| (*spelling, *kind))
            .collect::<Vec<_>>(),
        // Both parameter lists and the argument list are exact, so only the
        // callee's own obligation remains.
        vec![
            ("caller", ResolutionGapKind::UnsupportedVisibility),
            ("callee", ResolutionGapKind::UnsupportedCallApplicability),
        ],
        "every retained Rust applicability gap must identify its source site"
    );
    assert!(
        facts.reference_enumeration_gaps.is_empty(),
        "unexpected enumeration gaps: {:?}",
        facts.reference_enumeration_gaps
    );
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::for_test(b"rust-first-resolution-tranche"),
        crate::analyzer::resolution::test_shared_names(),
        Language::Rust,
        &facts,
    );
    assert!(!lowered.lexical().nodes().is_empty());
    assert!(!lowered.lexical().paths().is_empty());
    assert!(!lowered.lexical().semantics().is_empty());
    assert_eq!(lowered.lexical().gaps().len(), 2);
    assert!(lowered.lexical().gaps().iter().all(|gap| {
        matches!(
            gap.origin(),
            LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedCallApplicability
                    | ResolutionGapKind::UnsupportedVisibility
            )
        )
    }));
    assert_eq!(
        lowered
            .lexical()
            .gaps()
            .iter()
            .filter(|gap| matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. }))
            .count(),
        1,
        "only the gap on a real type slot retains typed coverage"
    );
    assert_eq!(
        lowered
            .lexical()
            .gaps()
            .iter()
            .filter(|gap| { matches!(gap.frontier(), LoweringCoverageFrontier::Reference { .. }) })
            .count(),
        1,
        "the callee applicability gap retains one positioned reference frontier"
    );
    assert!(!lowered.lexical().gaps().iter().any(|gap| {
        matches!(
            gap.frontier(),
            LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Forward,
                ..
            }
        )
    }));
    let mut lowered_gap_sites = lowered
        .lexical()
        .gaps()
        .iter()
        .map(|gap| {
            let site = facts.sites[gap.site().index()];
            &source[site.start_byte..site.end_byte]
        })
        .collect::<Vec<_>>();
    lowered_gap_sites.sort_unstable();
    assert_eq!(
        lowered_gap_sites,
        vec!["callee", "caller"],
        "lowered coverage keeps positioned and real-slot gap rows"
    );

    let ResolutionInteriorPreparation::Prepared(prepared) =
        prepare_resolution_bundle_with_unit_keys(
            &lowered,
            Some(&unit_keys),
            &CancellationToken::default(),
        )
    else {
        panic!("uncancelled Rust first-tranche preparation must finish");
    };
    for family in [
        "expected_semantic_site_count",
        "expected_path_endpoint_header_count",
    ] {
        let index = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .position(|column| *column == family)
            .unwrap_or_else(|| panic!("manifest has {family}"));
        assert!(prepared.family_counts()[index] > 0, "{family}");
    }
}

#[cfg(test)]
#[test]
fn unresolved_expression_macro_does_not_duplicate_reverse_gap_candidate() {
    let source = "fn caller() { external_macro!(); }\n";
    let file = ProjectFile::new(
        fixture_project_root("unresolved-expression-macro-reverse-gap-candidate"),
        "lib.rs",
    );
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    let tree = parser.parse(source, None).expect("parse Rust fixture");
    let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
    let source_facts = parsed
        .source_facts
        .as_ref()
        .expect("Rust parser publishes canonical source facts");
    assert_eq!(source_facts.rust_items.macro_inputs.len(), 1);
    let (macro_site, _) = source_facts.rust_items.macro_inputs[0]
        .native_frontier
        .expect("unresolved expression macro has a native frontier");
    assert!(parsed.resolution_facts.gaps.iter().any(|gap| {
        gap.site == macro_site && gap.kind == ResolutionGapKind::UnsupportedExpression
    }));

    let unit_keys = parsed_unit_keys(&parsed);
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::for_test(b"unresolved-expression-macro-reverse-gap-candidate"),
        crate::analyzer::resolution::test_shared_names(),
        Language::Rust,
        &parsed.resolution_facts,
    );
    assert!(
        lowered
            .common()
            .rust_reverse_gap_candidates
            .iter()
            .any(|candidate| candidate.site == macro_site)
    );
    let ResolutionInteriorPreparation::Prepared(prepared) =
        prepare_resolution_bundle_with_source_facts(
            &lowered,
            &unit_keys,
            Some(source_facts),
            Some(source),
            &CancellationToken::default(),
        )
        .expect("prepare unresolved expression macro resolution bundle")
    else {
        panic!("uncancelled unresolved macro preparation must finish");
    };
    let count_index = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .position(|column| *column == "expected_rust_reverse_gap_candidate_count")
        .expect("Rust reverse gap candidate family");
    assert!(
        prepared.family_counts()[count_index] > 0,
        "the unresolved macro frontier retains a reverse gap candidate"
    );
}

#[cfg(test)]
#[test]
fn rust_m6a_first_tranche_facts_all_prepare() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    for (path, source) in brokk_bifrost_rust::resolution_spike_fixture::M6A_RUST_WORKSPACE_FILES
        .iter()
        .filter(|(path, _)| path.ends_with(".rs"))
    {
        let file = ProjectFile::new(
            fixture_project_root("selected-rust-context-does-not-touch-disk"),
            *path,
        );
        let tree = parser.parse(source, None).expect("parse Rust spike file");
        let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
        let unit_keys = parsed_unit_keys(&parsed);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(path.as_bytes()),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &parsed.resolution_facts,
        );
        assert!(
            matches!(
                prepare_resolution_bundle_with_unit_keys(
                    &lowered,
                    Some(&unit_keys),
                    &CancellationToken::default(),
                ),
                ResolutionInteriorPreparation::Prepared(_)
            ),
            "{path}"
        );
    }
}

#[cfg(test)]
#[test]
fn complete_analysis_queries_seek_persistent_authority_tables() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let request = CompleteAnalysisBlobRequest::new(
        oid(b"complete analysis query plan"),
        PRIMARY,
        [PROJECTION.to_owned()],
    );
    let conn = store.conn.lock().expect("store mutex");
    sync_requested_parsed_blobs(
        &conn,
        &[(request.oid(), request.storage_language().to_owned())],
    )
    .expect("sync requested primary");
    sync_requested_analysis_projections(&conn, std::slice::from_ref(&request))
        .expect("sync requested projections");

    let explain = |sql: &str| {
        conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare complete-analysis plan")
            .query_map([Language::Java.config_label()], |row| {
                row.get::<_, String>(3)
            })
            .expect("query complete-analysis plan")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("read complete-analysis plan")
    };
    let missing_plan = explain(MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL);
    let projection_plan = explain(REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL);

    assert_bounded_complete_analysis_plan(&missing_plan);
    assert_bounded_complete_analysis_plan(&projection_plan);

    for (alias, index) in [
        ("primary_epoch", "PRIMARY KEY"),
        ("primary_resolution_epoch", "PRIMARY KEY"),
        ("primary_blob", "idx_blobs_lang_generation"),
        ("primary_meta", "PRIMARY KEY"),
        ("primary_interior", "PRIMARY KEY"),
        ("projection", "PRIMARY KEY"),
        ("independent", "PRIMARY KEY"),
        ("projection_epoch", "PRIMARY KEY"),
        ("projection_resolution_epoch", "PRIMARY KEY"),
        ("projection_meta", "PRIMARY KEY"),
        ("projection_interior", "PRIMARY KEY"),
    ] {
        assert_plan_search(&missing_plan, alias, index);
    }
    assert_plan_search(&missing_plan, "projection_blob", "sqlite_autoindex_blobs_1");
    assert_plan_search(&missing_plan, "projection_blob", "(blob_oid=? AND lang=?)");
    assert!(
        missing_plan
            .iter()
            .any(|detail| detail.contains("CORRELATED SCALAR SUBQUERY")),
        "optional projection validation must remain a per-request indexed probe: {missing_plan:#?}"
    );

    for (alias, index) in [
        ("owner", "PRIMARY KEY"),
        ("independent", "PRIMARY KEY"),
        ("projection_epoch", "PRIMARY KEY"),
        ("projection_resolution_epoch", "PRIMARY KEY"),
        ("projection_meta", "PRIMARY KEY"),
        ("projection_interior", "PRIMARY KEY"),
    ] {
        assert_plan_search(&projection_plan, alias, index);
    }
    assert_plan_search(
        &projection_plan,
        "projection_blob",
        "sqlite_autoindex_blobs_1",
    );
    assert_plan_search(
        &projection_plan,
        "projection_blob",
        "(blob_oid=? AND lang=?)",
    );
}

#[cfg(test)]
#[test]
fn stale_generation_reclamation_cost_plan_uses_gc_order_and_keyed_probes() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let conn = store.conn.lock().expect("store mutex");
    let plan = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            stale_generation_blob_costs_sql()
        ))
        .expect("prepare stale-generation GC plan")
        .query_map([], |row| row.get::<_, String>(3))
        .expect("query stale-generation GC plan")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("read stale-generation GC plan");

    let scans = plan
        .iter()
        .filter_map(|detail| {
            detail
                .split_once("SCAN ")
                .and_then(|(_, tail)| tail.split_ascii_whitespace().next())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scans,
        vec!["blobs"],
        "GC may scan only the ordered blob inventory: {plan:#?}"
    );
    assert!(
        plan.iter().any(|detail| {
            detail.contains("SCAN blobs USING COVERING INDEX idx_blobs_lang_generation")
        }),
        "GC must consume stale blobs in its indexed order: {plan:#?}"
    );
    for alias in [
        "epochs",
        "meta",
        "costs",
        "manifest",
        "reference_manifest",
        "interior",
    ] {
        assert_plan_search(&plan, alias, "PRIMARY KEY");
    }
    // Schema 117 left one `facts` alias in the reclamation cost: the canonical
    // source-fact manifest. The four retired `structural_fact_*` families each
    // had one of the other probes.
    assert_eq!(
        plan.iter()
            .filter(|detail| detail.contains("SEARCH facts USING PRIMARY KEY"))
            .count(),
        1,
        "the canonical source-fact family must be a keyed correlated probe: {plan:#?}"
    );
    assert!(
        plan.iter()
            .all(|detail| { !detail.contains("AUTOMATIC") && !detail.contains("USE TEMP B-TREE") }),
        "GC must not synthesize an index or sort its ordered inventory: {plan:#?}"
    );
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod producer_test_support {
    use super::*;

    use crate::hash::HashMap;

    #[doc(hidden)]
    pub const PRIMARY: &str = "java";
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const PROJECTION: &str = "java:projection";
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn generations(store: &AnalyzerStore) -> HashMap<String, GenerationId> {
        let mut generations = HashMap::default();
        for language in [PRIMARY, PROJECTION] {
            generations.insert(
                language.to_owned(),
                store
                    .ensure_language_epoch_value(language, "resolution-producer-test-v1")
                    .expect("test generation"),
            );
        }
        generations
    }

    /// Declares a member under `shared_route` and calls it through a receiver, so
    /// it is the one blob that holds a qualified route under the name.
    #[doc(hidden)]
    pub const ROUTE_ISOLATING_HOLDER: &str = concat!(
        "pub struct Router;\n",
        "impl Router { pub fn shared_route(&self) -> usize { 0 } }\n",
        "pub fn hold(value: Router) -> usize { value.shared_route() }\n",
    );
    /// Declares a member under `shared_member` and never calls it, so it is the
    /// one blob that declares a deferred member owner under the name.
    #[doc(hidden)]
    pub const MEMBER_ISOLATING_HOLDER: &str = concat!(
        "pub struct Owner;\n",
        "impl Owner { pub fn shared_member(&self) -> usize { 0 } }\n",
    );
}

#[cfg(test)]
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_producer_tests_go_support::go_extraction_support_10::*;
