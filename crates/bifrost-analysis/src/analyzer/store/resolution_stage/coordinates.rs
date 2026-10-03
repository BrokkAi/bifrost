//! One assigned capsule catalog, converted to batch parameters and dropped
//! after admission. Its persisted correspondence is active-stage SQL authority.

use super::{codec, lexical::semantic_cells};
use crate::CancellationToken;
use crate::analyzer::resolution::{
    LoweredRootImportProvenance, ResolutionIdentityCatalog, SelectedResolutionMountOrdinal,
};
use crate::analyzer::store::{Result, resolution_lexical::hex_digest};
use rusqlite::{Connection, params};
use serde_json::json;

pub(super) struct PreparedStageCoordinates {
    semantics: String,
    nodes: String,
    paths: String,
    variables: String,
    package_references: String,
    package_members: String,
    go_package_imports: String,
}

impl PreparedStageCoordinates {
    pub(super) fn new(
        assigned: &ResolutionIdentityCatalog,
        imports: &[LoweredRootImportProvenance],
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let provenance = imports
            .iter()
            .map(|row| (row.token, row))
            .collect::<crate::hash::HashMap<_, _>>();
        let mut semantics = Vec::with_capacity(assigned.semantics().len());
        for &(runtime, identity) in assigned.semantics() {
            if cancellation.is_cancelled() {
                return None;
            }
            let (key, shared) = semantic_cells(runtime);
            semantics.push(json!([
                key,
                shared,
                hex_digest(assigned.identity_hash_bytes(identity)),
                provenance.get(&runtime).map(|row| row.source_site.get()),
                provenance.get(&runtime).map(|row| row.start_byte),
                provenance.get(&runtime).map(|row| row.end_byte),
                provenance.get(&runtime).map(|row| crate::analyzer::store::resolution_prepare::resolution_rows::import_route_kind_label(row.kind))
            ]));
        }
        let mut nodes = Vec::with_capacity(assigned.nodes().len());
        for &(runtime, identity) in assigned.nodes() {
            if cancellation.is_cancelled() {
                return None;
            }
            nodes.push(json!([
                codec::encode_node(runtime),
                hex_digest(identity.digest()),
                assigned
                    .source_scope_ordinals()
                    .get(&runtime)
                    .map(|scope| scope.get())
            ]));
        }
        let mut paths = Vec::with_capacity(assigned.paths().len());
        for &(runtime, identity) in assigned.paths() {
            if cancellation.is_cancelled() {
                return None;
            }
            paths.push(json!([
                codec::encode_path_id(runtime),
                hex_digest(identity.digest())
            ]));
        }
        let mut variables = Vec::with_capacity(assigned.stack_variables().len());
        for &(runtime, identity) in assigned.stack_variables() {
            if cancellation.is_cancelled() {
                return None;
            }
            variables.push(json!([
                i64::try_from(runtime.get()).expect("a runtime variable fits a SQLite integer"),
                hex_digest(identity.digest())
            ]));
        }
        (!cancellation.is_cancelled()).then(|| Self {
            semantics: serde_json::to_string(&semantics).expect("coordinate parameters serialize"),
            nodes: serde_json::to_string(&nodes).expect("coordinate parameters serialize"),
            paths: serde_json::to_string(&paths).expect("coordinate parameters serialize"),
            variables: serde_json::to_string(&variables).expect("coordinate parameters serialize"),
            package_references: "[]".into(),
            package_members: "[]".into(),
            go_package_imports: "[]".into(),
        })
    }

    pub(super) fn with_package_metadata(
        mut self,
        references: &[crate::analyzer::resolution::LoweredPackageReference],
        members: &[crate::analyzer::resolution::LoweredPackageMember],
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut reference_rows = Vec::with_capacity(references.len());
        for row in references {
            if cancellation.is_cancelled() {
                return None;
            }
            reference_rows.push(serde_json::json!([
                semantic_cells(row.token).0.expect("package token is local"),
                semantic_cells(row.domain)
                    .1
                    .expect("package domain is shared"),
                semantic_cells(row.reference)
                    .0
                    .expect("package reference is local"),
                row.source_site.get(),
                codec::encode_node(row.root_scope),
                row.namespace.label(),
                semantic_cells(row.lookup)
                    .1
                    .expect("package lookup is shared")
            ]));
        }
        let mut member_rows = Vec::with_capacity(members.len());
        for row in members {
            if cancellation.is_cancelled() {
                return None;
            }
            member_rows.push(serde_json::json!([
                semantic_cells(row.token).0.expect("package token is local"),
                semantic_cells(row.domain)
                    .1
                    .expect("package domain is shared"),
                semantic_cells(row.definition)
                    .0
                    .expect("package definition is local"),
                row.source_site.get(),
                codec::encode_node(row.root_scope),
                row.namespace.label(),
                semantic_cells(row.lookup)
                    .1
                    .expect("package lookup is shared")
            ]));
        }
        self.package_references =
            serde_json::to_string(&reference_rows).expect("package rows serialize");
        self.package_members = serde_json::to_string(&member_rows).expect("package rows serialize");
        (!cancellation.is_cancelled()).then_some(self)
    }

    pub(super) fn with_go_import_metadata(
        mut self,
        imports: &[crate::analyzer::resolution::LoweredGoPackageImport],
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut rows = Vec::with_capacity(imports.len());
        for import in imports {
            if cancellation.is_cancelled() {
                return None;
            }
            rows.push(json!([
                semantic_cells(import.definition)
                    .0
                    .expect("Go import definition is local"),
                import.source_site.get(),
                codec::encode_node(import.file_scope),
                semantic_cells(import.spelling_choice)
                    .0
                    .expect("Go import choice is local"),
                import.start_byte,
                import.end_byte,
                import.kind.label(),
            ]));
        }
        self.go_package_imports = serde_json::to_string(&rows).expect("Go import rows serialize");
        (!cancellation.is_cancelled()).then_some(self)
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        let mut digest = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-selected-stage-coordinates:v1",
        );
        digest.field("semantics", self.semantics.as_bytes());
        digest.field("nodes", self.nodes.as_bytes());
        digest.field("paths", self.paths.as_bytes());
        digest.field("variables", self.variables.as_bytes());
        digest.field("package_references", self.package_references.as_bytes());
        digest.field("package_members", self.package_members.as_bytes());
        digest.field("go_package_imports", self.go_package_imports.as_bytes());
        digest.finish()
    }

    /// Count equality plus an indexed dense-key comparison rejects a changed,
    /// reordered, missing or additional assignment, even for the same witness.
    pub(super) fn agrees(&self, connection: &Connection, producer: i64) -> Result<bool> {
        connection.prepare_cached(r#"
SELECT
 (SELECT COUNT(*) FROM temp.selected_resolution_stage_semantic_coordinates WHERE producer_id=?1)=json_array_length(?2)
 AND NOT EXISTS(SELECT 1 FROM json_each(?2) expected
 LEFT JOIN temp.selected_resolution_stage_semantic_coordinates actual
 ON actual.producer_id=?1 AND actual.dense_key=expected.key
 WHERE actual.runtime_key IS NOT expected.value->>0
 OR actual.shared_id IS NOT expected.value->>1
 OR actual.identity_digest IS NOT unhex(expected.value->>2)
 OR actual.import_source_site IS NOT expected.value->>3
 OR actual.import_start_byte IS NOT expected.value->>4
 OR actual.import_end_byte IS NOT expected.value->>5
 OR actual.import_route_kind IS NOT expected.value->>6)
 AND (SELECT COUNT(*) FROM temp.selected_resolution_stage_node_coordinates WHERE producer_id=?1)=json_array_length(?3)
 AND NOT EXISTS(SELECT 1 FROM json_each(?3) expected
 LEFT JOIN temp.selected_resolution_stage_node_coordinates actual
 ON actual.producer_id=?1 AND actual.dense_key=expected.key
 WHERE actual.runtime_key IS NOT expected.value->>0
 OR actual.identity_digest IS NOT unhex(expected.value->>1)
 OR actual.source_scope IS NOT expected.value->>2)
 AND (SELECT COUNT(*) FROM temp.selected_resolution_stage_path_coordinates WHERE producer_id=?1)=json_array_length(?4)
 AND NOT EXISTS(SELECT 1 FROM json_each(?4) expected
 LEFT JOIN temp.selected_resolution_stage_path_coordinates actual
 ON actual.producer_id=?1 AND actual.dense_key=expected.key
 WHERE actual.runtime_key IS NOT expected.value->>0
 OR actual.identity_digest IS NOT unhex(expected.value->>1))
 AND (SELECT COUNT(*) FROM temp.selected_resolution_stage_variable_coordinates WHERE producer_id=?1)=json_array_length(?5)
 AND NOT EXISTS(SELECT 1 FROM json_each(?5) expected
 LEFT JOIN temp.selected_resolution_stage_variable_coordinates actual
 ON actual.producer_id=?1 AND actual.dense_key=expected.key
 WHERE actual.runtime_key IS NOT expected.value->>0
 OR actual.identity_digest IS NOT unhex(expected.value->>1))
 AND (SELECT count(*) FROM temp.selected_resolution_stage_package_references WHERE producer_id=?1)=json_array_length(?6)
 AND NOT EXISTS(SELECT 1 FROM json_each(?6) expected
 LEFT JOIN temp.selected_resolution_stage_package_references actual
 ON actual.producer_id=?1 AND actual.token_key=expected.value->>0 AND actual.reference_key=expected.value->>2
 WHERE actual.domain_shared IS NOT expected.value->>1 OR actual.source_site IS NOT expected.value->>3
 OR actual.root_scope_key IS NOT expected.value->>4 OR actual.namespace IS NOT expected.value->>5 OR actual.lookup_shared IS NOT expected.value->>6)
 AND (SELECT count(*) FROM temp.selected_resolution_stage_package_members WHERE producer_id=?1)=json_array_length(?7)
 AND NOT EXISTS(SELECT 1 FROM json_each(?7) expected
 LEFT JOIN temp.selected_resolution_stage_package_members actual
 ON actual.producer_id=?1 AND actual.token_key=expected.value->>0 AND actual.definition_key=expected.value->>2
 WHERE actual.domain_shared IS NOT expected.value->>1 OR actual.source_site IS NOT expected.value->>3
 OR actual.root_scope_key IS NOT expected.value->>4 OR actual.namespace IS NOT expected.value->>5 OR actual.lookup_shared IS NOT expected.value->>6)
 AND (SELECT count(*) FROM temp.selected_resolution_stage_go_package_imports WHERE producer_id=?1)=json_array_length(?8)
 AND NOT EXISTS(SELECT 1 FROM json_each(?8) expected
 LEFT JOIN temp.selected_resolution_stage_go_package_imports actual
 ON actual.producer_id=?1 AND actual.definition_key=expected.value->>0
 WHERE actual.source_site IS NOT expected.value->>1 OR actual.file_scope_key IS NOT expected.value->>2
 OR actual.spelling_choice_key IS NOT expected.value->>3 OR actual.start_byte IS NOT expected.value->>4
 OR actual.end_byte IS NOT expected.value->>5 OR actual.kind IS NOT expected.value->>6)
"#)?.query_row(params![producer, self.semantics, self.nodes, self.paths, self.variables, self.package_references, self.package_members, self.go_package_imports], |row| row.get(0)).map_err(Into::into)
    }

    pub(super) fn insert(
        &self,
        connection: &Connection,
        producer: i64,
        host: SelectedResolutionMountOrdinal,
    ) -> Result<()> {
        if self.go_package_imports != "[]" {
            connection.prepare_cached(
                "INSERT INTO temp.selected_resolution_stage_go_package_imports(host_ordinal,producer_id,definition_key,source_site,file_scope_key,spelling_choice_key,start_byte,end_byte,kind) SELECT ?1,?2,value->>0,value->>1,value->>2,value->>3,value->>4,value->>5,value->>6 FROM json_each(?3)"
            )?.execute(params![host.get(), producer, self.go_package_imports])?;
        }
        for (table, target, rows) in [
            (
                "selected_resolution_stage_package_references",
                "reference_key",
                &self.package_references,
            ),
            (
                "selected_resolution_stage_package_members",
                "definition_key",
                &self.package_members,
            ),
        ] {
            // Most generated fragments (including Rust contexts) have no
            // package authority. Avoid preparing two no-op INSERT statements
            // for every such projection; replay checks still verify absence.
            if rows == "[]" {
                continue;
            }
            let sql = format!(
                "INSERT INTO temp.{table}(host_ordinal,producer_id,token_key,domain_shared,{target},source_site,root_scope_key,namespace,lookup_shared) SELECT ?1,?2,value->>0,value->>1,value->>2,value->>3,value->>4,value->>5,value->>6 FROM json_each(?3)"
            );
            connection
                .prepare_cached(&sql)?
                .execute(params![host.get(), producer, rows])?;
        }
        connection
            .prepare_cached(
                r#"
INSERT INTO temp.selected_resolution_stage_semantic_coordinates
 (host_ordinal,producer_id,dense_key,runtime_key,shared_id,identity_digest,import_source_site,import_start_byte,import_end_byte,import_route_kind)
SELECT ?1,?2,key,value->>0,value->>1,unhex(value->>2),value->>3,value->>4,value->>5,value->>6 FROM json_each(?3)
"#,
            )?
            .execute(params![host.get(), producer, self.semantics])?;
        connection
            .prepare_cached(
                r#"
INSERT INTO temp.selected_resolution_stage_node_coordinates
 (host_ordinal,producer_id,dense_key,runtime_key,identity_digest,source_scope)
SELECT ?1,?2,key,value->>0,unhex(value->>1),value->>2 FROM json_each(?3)
"#,
            )?
            .execute(params![host.get(), producer, self.nodes])?;
        connection
            .prepare_cached(
                r#"
INSERT INTO temp.selected_resolution_stage_path_coordinates
 (host_ordinal,producer_id,dense_key,runtime_key,identity_digest)
SELECT ?1,?2,key,value->>0,unhex(value->>1) FROM json_each(?3)
"#,
            )?
            .execute(params![host.get(), producer, self.paths])?;
        connection
            .prepare_cached(
                r#"
INSERT INTO temp.selected_resolution_stage_variable_coordinates
 (host_ordinal,producer_id,dense_key,runtime_key,identity_digest)
SELECT ?1,?2,key,value->>0,unhex(value->>1) FROM json_each(?3)
"#,
            )?
            .execute(params![host.get(), producer, self.variables])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_capsule_requires_exact_runtime_correspondence() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(crate::analyzer::store::resolution_stage::schema_sql())
            .unwrap();
        connection.execute(
            "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(3,?1,?2)",
            params![[1u8; 32].as_slice(), [2u8; 32].as_slice()],
        ).unwrap();
        let producer = connection.last_insert_rowid();
        let runtime = (1_i64 << 60) + 17;
        let digest = hex_digest([9; 32]);
        let mut assigned = PreparedStageCoordinates {
            semantics: json!([[runtime, null, digest], [null, 27, digest]]).to_string(),
            nodes: json!([[runtime + 1, digest, 6]]).to_string(),
            paths: json!([[runtime + 2, digest]]).to_string(),
            variables: json!([[runtime + 3, digest]]).to_string(),
            package_references: json!([[runtime + 10, 41, runtime, 7, runtime + 1, "type", 42]])
                .to_string(),
            package_members: json!([[runtime + 11, 41, runtime + 12, 8, runtime + 1, "type", 42]])
                .to_string(),
            go_package_imports: json!([[
                runtime + 14,
                9,
                runtime + 1,
                runtime + 15,
                20,
                30,
                "named"
            ]])
            .to_string(),
        };
        assigned
            .insert(
                &connection,
                producer,
                SelectedResolutionMountOrdinal::new(3),
            )
            .unwrap();
        assert!(assigned.agrees(&connection, producer).unwrap());
        let imports = assigned.go_package_imports.clone();
        let import_digest = assigned.digest();
        assigned.go_package_imports =
            json!([[runtime + 14, 9, runtime + 1, runtime + 15, 20, 30, "blank"]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assert_ne!(import_digest, assigned.digest());
        assigned.go_package_imports = "[]".into();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.go_package_imports = imports;
        let package_members = assigned.package_members.clone();
        let package_digest = assigned.digest();
        assigned.package_members =
            json!([[runtime + 11, 43, runtime + 12, 8, runtime + 1, "type", 42]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assert_ne!(package_digest, assigned.digest());
        assigned.package_members = package_members;
        let package_references = assigned.package_references.clone();
        assigned.package_references = "[]".into();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.package_references = package_references;
        let original = assigned.semantics.clone();
        assigned.semantics = json!([[runtime + 4, null, digest], [null, 27, digest]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.semantics = json!([[null, 27, digest], [runtime, null, digest]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.semantics = json!([[runtime, null, digest]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.semantics = original;
        assigned.nodes = json!([[runtime + 1, digest, 7]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.nodes = json!([[runtime + 1, digest, 6]]).to_string();
        assigned.paths = json!([[runtime + 3, digest]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.paths = json!([[runtime + 2, hex_digest([8; 32])]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assigned.paths = json!([[runtime + 2, digest]]).to_string();
        assert!(assigned.agrees(&connection, producer).unwrap());
        let digest_before = assigned.digest();
        assigned.variables = json!([[runtime + 4, digest]]).to_string();
        assert!(!assigned.agrees(&connection, producer).unwrap());
        assert_ne!(digest_before, assigned.digest());
        assigned.variables = "[]".into();
        assert!(!assigned.agrees(&connection, producer).unwrap());
    }
}
