-- Rebuild from exactly the revision-valid summary predicate.
DELETE FROM temp.selected_rust_unit_closure;
DELETE FROM temp.selected_rust_unit_summaries;
INSERT INTO temp.selected_rust_unit_summaries
SELECT selected.workspace_id, selected.lang, selected.generation, selected.revision,
       versions.unit_key, versions.valid_from, versions.summary_id,
       rust_versions.manifest_file_version_id, rust_versions.topology_id
FROM selected_workspace_revisions AS selected
CROSS JOIN main.resolution_unit_summary_versions AS versions
  ON versions.workspace_id = selected.workspace_id
 AND versions.lang = selected.lang AND versions.generation = selected.generation
CROSS JOIN main.resolution_unit_summaries AS summaries
  ON summaries.summary_id = versions.summary_id
CROSS JOIN main.resolution_producer_epochs AS epochs
  ON epochs.lang = versions.lang AND epochs.producer_epoch = summaries.producer_epoch
CROSS JOIN main.rust_resolution_unit_summary_versions AS rust_versions
  ON rust_versions.workspace_id = versions.workspace_id
 AND rust_versions.lang = versions.lang AND rust_versions.generation = versions.generation
 AND rust_versions.unit_key = versions.unit_key AND rust_versions.valid_from = versions.valid_from
 AND rust_versions.summary_id = versions.summary_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  INDEXED BY rust_resolution_unit_summary_contexts_live
  ON contexts.summary_id = versions.summary_id
WHERE selected.lang = 'rust'
  AND versions.valid_from <= selected.revision
  AND (versions.valid_until IS NULL OR selected.revision < versions.valid_until)
  AND summaries.lang = 'rust' AND summaries.unit_kind = 'rust_crate'
  AND summaries.publication_state = 'complete'
  AND summaries.derivation_version = :rust_unit_summary_derivation_version;

INSERT INTO temp.selected_rust_unit_closure
WITH RECURSIVE closure(root_unit_key, unit_key, summary_id, topology_id, workspace_id, generation) AS (
 SELECT unit_key, unit_key, summary_id, topology_id, workspace_id, generation
 FROM selected_rust_unit_summaries
 UNION
 SELECT closure.root_unit_key, child.unit_key, child.summary_id, child.topology_id,
        child.workspace_id, child.generation
 FROM closure
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=closure.summary_id AND dependency.boundary='workspace'
 CROSS JOIN selected_rust_unit_summaries AS child
  ON child.unit_key=dependency.dependency_unit_key
 AND child.workspace_id=closure.workspace_id AND child.generation=closure.generation
)
SELECT * FROM closure;
