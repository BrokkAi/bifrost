//! Deterministic JVM context derived from one immutable source/config snapshot.
//! Only SQLite rows survive reconciliation. Rust holds one pom's parsed facts
//! at a time; source membership is inserted by indexed selected-row queries.

use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::path_normalization::NormalizePath;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{AnalyzerStore, Result, WorkspaceSnapshotId, WorkspaceSnapshots};
use crate::analyzer::store::maven::MavenConfigurationFacts;
use crate::analyzer::store::maven::MavenModelLimitation;
use crate::analyzer::store::maven::MavenValue;
use crate::analyzer::store::maven::maven_configuration_from_bytes;

pub(crate) const JVM_CONTEXT_DERIVATION_VERSION: i64 = 1;

pub(super) const JVM_NATIVE_SOURCE_MEMBERSHIP_SQL: &str =
    "INSERT INTO jvm_source_root_files(context_id,root_id,source_file_version_id)
     SELECT context_id,?2,file_version_id FROM jvm_selected_source_files
     WHERE context_id=?1 AND rel_path>=?3 AND rel_path<?4";

impl AnalyzerStore {
    #[doc(hidden)]
    pub fn reconcile_jvm_package_contexts(&self, snapshots: &WorkspaceSnapshots) -> Result<()> {
        for language in ["java", "kotlin", "scala"] {
            if let Some(snapshot) = snapshots.get(language) {
                self.reconcile_jvm_package_context(snapshot)?;
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn reconcile_jvm_package_context(&self, snapshot: &WorkspaceSnapshotId) -> Result<i64> {
        assert!(matches!(
            snapshot.lang.as_str(),
            "java" | "kotlin" | "scala"
        ));
        let snapshot = snapshot.clone();
        self.conn.execute(move |connection| {
            // Reserve the writer before reading; a deferred snapshot upgrade can
            // fail immediately under contention despite the configured busy timeout.
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            super::require_current_generation(&tx, &snapshot.lang, snapshot.generation)?;
            let existing = tx.query_row(
                "SELECT context_id FROM jvm_context_revisions
                 WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND revision=?4 AND derivation_version=?5",
                params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision, JVM_CONTEXT_DERIVATION_VERSION],
                |row| row.get(0),
            ).optional()?;
            if let Some(context_id) = existing {
                return Ok(context_id);
            }
            tx.execute(
                "INSERT INTO jvm_context_revisions(workspace_id,lang,generation,revision,derivation_version)
                 VALUES(?1,?2,?3,?4,?5)",
                params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision, JVM_CONTEXT_DERIVATION_VERSION],
            )?;
            let context_id = tx.last_insert_rowid();
            let mut parsed_project = false;
            {
                let mut statement = tx.prepare(
                    "SELECT file_version_id,rel_path,source_bytes FROM jvm_selected_configuration_files
                     WHERE context_id=?1 ORDER BY rel_path",
                )?;
                let mut configurations = statement.query([context_id])?;
                while let Some(row) = configurations.next()? {
                    let file_version_id: i64 = row.get(0)?;
                    let relative_path: String = row.get(1)?;
                    let path = Path::new(&relative_path);
                    match path.file_name().and_then(|name| name.to_str()) {
                        Some("pom.xml") => {
                            let bytes: Option<Vec<u8>> = row.get(2)?;
                            let facts = bytes.as_deref().and_then(|bytes| maven_configuration_from_bytes(path, bytes));
                            if let Some(facts) = facts {
                                publish_project(&tx, context_id, file_version_id, &relative_path, facts)?;
                                parsed_project = true;
                            } else {
                                insert_gap(&tx, context_id, None, Some(file_version_id),
                                    "maven_configuration_unavailable", &relative_path)?;
                            }
                        }
                        Some("build.gradle" | "build.gradle.kts" | "settings.gradle" | "settings.gradle.kts") => {
                            insert_gap(&tx, context_id, None, Some(file_version_id),
                                "gradle_topology_unsupported", &relative_path)?;
                        }
                        _ => {}
                    }
                }
            }
            if !parsed_project {
                insert_gap(&tx, context_id, None, None, "jvm_source_roots_unavailable",
                    "No readable selected Maven project declares a default source layout")?;
            }
            // These source declarations do not identify selected JDK/dependency
            // artifact bytes. Later artifact authority may discharge this gap.
            insert_gap(&tx, context_id, None, None, "jvm_external_inventory_unavailable",
                "Selected source/configuration facts do not certify JDK or external artifacts")?;
            tx.execute(
                "INSERT INTO jvm_context_gaps(context_id,input_file_version_id,code,evidence)
                 SELECT f.context_id,f.file_version_id,'source_root_unowned',f.rel_path
                 FROM jvm_selected_source_files AS f
                 WHERE f.context_id=?1 AND NOT EXISTS(
                   SELECT 1 FROM jvm_source_root_files AS m
                   WHERE m.context_id=f.context_id AND m.source_file_version_id=f.file_version_id)",
                [context_id],
            )?;
            tx.execute(
                "INSERT INTO jvm_context_gaps(context_id,input_file_version_id,code,evidence)
                 SELECT m.context_id,m.source_file_version_id,'source_root_ambiguous',
                        f.rel_path || ': ' || group_concat(r.root_path, ', ')
                 FROM jvm_source_root_files AS m
                 JOIN jvm_source_roots AS r ON r.context_id=m.context_id AND r.root_id=m.root_id
                 JOIN jvm_selected_source_files AS f ON f.context_id=m.context_id AND f.file_version_id=m.source_file_version_id
                 WHERE m.context_id=?1 GROUP BY m.context_id,m.source_file_version_id HAVING COUNT(*)>1",
                [context_id],
            )?;
            tx.commit()?;
            Ok(context_id)
        })
    }
}

fn value_columns(value: &MavenValue) -> (&'static str, Option<&str>) {
    match value {
        MavenValue::Missing => ("missing", None),
        MavenValue::Unresolved => ("unresolved", None),
        MavenValue::Resolved(value) => ("resolved", Some(value)),
    }
}

fn insert_gap(
    tx: &Transaction<'_>,
    context_id: i64,
    project_id: Option<i64>,
    input_file_version_id: Option<i64>,
    code: &str,
    evidence: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO jvm_context_gaps(context_id,project_id,input_file_version_id,code,evidence)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            context_id,
            project_id,
            input_file_version_id,
            code,
            evidence
        ],
    )?;
    Ok(())
}

fn publish_project(
    tx: &Transaction<'_>,
    context_id: i64,
    file_version_id: i64,
    pom_path: &str,
    facts: MavenConfigurationFacts,
) -> Result<()> {
    let (version_state, version_value) = value_columns(&facts.version);
    let directory = crate::path_utils::normalize_pattern(&facts.directory.to_string_lossy());
    tx.execute(
        "INSERT INTO jvm_projects(context_id,pom_file_version_id,directory,group_id,artifact_id,version_state,version_value)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![context_id,file_version_id,directory,facts.group_id,facts.artifact_id,version_state,version_value],
    )?;
    let project_id = tx.last_insert_rowid();
    // An explicit custom layout contradicts default-root ownership. Keep
    // those selected source files unowned until that layout is interpreted.
    if !facts
        .limitations
        .contains(&MavenModelLimitation::CustomSourceRoots)
    {
        for (role, root) in facts.default_source_roots() {
            let root = crate::path_utils::normalize_pattern(&root.to_string_lossy());
            tx.execute(
            "INSERT INTO jvm_source_roots(context_id,project_id,role,root_path) VALUES(?1,?2,?3,?4)",
            params![context_id,project_id,role,root],
        )?;
            let root_id = tx.last_insert_rowid();
            // Normalized SQL paths use '/'. Its immediate ASCII successor '0'
            // bounds exactly the subtree prefix, without glob metacharacters.
            tx.execute(
                JVM_NATIVE_SOURCE_MEMBERSHIP_SQL,
                params![context_id, root_id, format!("{root}/"), format!("{root}0")],
            )?;
        }
    }
    for limitation in &facts.limitations {
        let code = match limitation {
            MavenModelLimitation::ParentModel => "maven_parent_model_unresolved",
            MavenModelLimitation::Profiles => "maven_profiles_unresolved",
            MavenModelLimitation::DependencyManagement => "maven_dependency_management_unresolved",
            MavenModelLimitation::CustomSourceRoots => "maven_custom_source_roots_unresolved",
            MavenModelLimitation::BuildPlugins => "maven_build_plugins_unresolved",
        };
        insert_gap(tx, context_id, Some(project_id), None, code, pom_path)?;
    }
    for module in &facts.modules {
        let selected_path = match module {
            MavenValue::Resolved(module) => selected_module_path(&facts.directory, module),
            MavenValue::Missing | MavenValue::Unresolved => None,
        };
        let selected = if let Some(path) = &selected_path {
            let path = crate::path_utils::normalize_pattern(&path.to_string_lossy());
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM jvm_selected_configuration_files WHERE context_id=?1 AND rel_path=?2)",
                params![context_id,path], |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if !selected {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_module_unavailable",
                &format!("{pom_path}: {module:?}"),
            )?;
        }
    }
    for dependency in &facts.dependencies {
        let group = value_columns(&dependency.group_id);
        let artifact = value_columns(&dependency.artifact_id);
        let version = value_columns(&dependency.version);
        let artifact_type = value_columns(&dependency.artifact_type);
        let classifier = value_columns(&dependency.classifier);
        let scope = value_columns(&dependency.scope);
        let optional = value_columns(&dependency.optional);
        tx.execute(
            "INSERT INTO jvm_direct_dependencies(context_id,project_id,ordinal,
               group_id_state,group_id_value,artifact_id_state,artifact_id_value,version_state,version_value,
               artifact_type_state,artifact_type_value,classifier_state,classifier_value,scope_state,scope_value,optional_state,optional_value)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![context_id,project_id,dependency.ordinal,group.0,group.1,artifact.0,artifact.1,version.0,version.1,
                artifact_type.0,artifact_type.1,classifier.0,classifier.1,scope.0,scope.1,optional.0,optional.1],
        )?;
        let unresolved = [
            ("groupId", &dependency.group_id),
            ("artifactId", &dependency.artifact_id),
            ("version", &dependency.version),
            ("type", &dependency.artifact_type),
            ("classifier", &dependency.classifier),
            ("scope", &dependency.scope),
            ("optional", &dependency.optional),
        ]
        .into_iter()
        .filter_map(|(name, value)| matches!(value, MavenValue::Unresolved).then_some(name))
        .collect::<Vec<_>>();
        if !unresolved.is_empty() {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_dependency_values_unresolved",
                &format!(
                    "{pom_path}, dependency {}: {unresolved:?}",
                    dependency.ordinal
                ),
            )?;
        }
        if [
            &dependency.group_id,
            &dependency.artifact_id,
            &dependency.version,
        ]
        .into_iter()
        .any(|value| matches!(value, MavenValue::Missing))
        {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_dependency_coordinates_partial",
                &format!(
                    "{pom_path}, dependency {}: group={:?}, artifact={:?}, version={:?}",
                    dependency.ordinal,
                    dependency.group_id,
                    dependency.artifact_id,
                    dependency.version
                ),
            )?;
        }
    }
    Ok(())
}

/// Resolve module paths lexically without permitting an escape or consulting
/// current disk contents. NormalizePath alone would erase a leading escape.
#[doc(hidden)]
pub fn selected_module_path(directory: &Path, module: &str) -> Option<PathBuf> {
    let candidate = directory
        .join(crate::path_utils::normalize_pattern(module))
        .join("pom.xml");
    let mut depth = 0usize;
    for component in candidate.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => depth = depth.checked_sub(1)?,
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    crate::path_utils::workspace_rel_path(&candidate.normalize().to_string_lossy())
}
