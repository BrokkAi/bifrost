-- Arity excludes an impossible target independently of receiver uncertainty.
-- x.m(a,b) compares two actuals to formals EXCLUDING the receiver;
-- T::m(x,a,b) compares three actuals to formals INCLUDING the receiver.
-- A free function has no receiver in either form. For calls that pass this
-- structural proof, open-member, TypeUnion and undecided-receiver retention
-- still runs unchanged during forward confirmation.
SELECT CASE
  -- Missing/recovered metadata, macro-derived occurrences and gap candidates
  -- are not exact authored call shapes; they retain their inventory doubt.
  WHEN site.site_kind IS NULL THEN 1
  -- Every qualified/callable reference has coarse lookup/applicability
  -- placeholders. Those do not imply missing call syntax. Other gap
  -- candidates keep their uncertainty, including macro-frontier shapes;
  -- transcribers also lack the exact-argument eligibility checked below.
  WHEN EXISTS (
    SELECT 1 FROM resolution_rust_reverse_gap_candidates AS gap
    WHERE gap.blob_id=mount.blob_id AND gap.site=site.site
      AND EXISTS (
        SELECT 1 FROM resolution_gap_reasons AS reason
          INDEXED BY resolution_gap_reasons_site
        WHERE reason.blob_id=gap.blob_id AND reason.site=gap.site
          AND reason.origin NOT IN (?9,?10)
      )
  ) THEN 1
  WHEN json_extract(arena.spans,'$[' || context.source_occurrence || '][4]') IS NOT ?8 THEN 1
  WHEN obligation.callee_reference IS NULL
       AND site.site_kind<>?4
       AND NOT (site.site_kind=?5 AND site.namespace=?6) THEN 0
  -- An absent obligation or exact-argument eligibility means unknown actuals,
  -- including empty-looking macro transcribers and cfg-attributed arguments.
  WHEN obligation.callee_reference IS NULL OR NOT EXISTS (
    SELECT 1 FROM json_each(obligation.eligible_rules) AS rule WHERE rule.value=?7
  ) THEN 1
  -- The signature reader returns NULL if any target alternative has unknown
  -- arity. Never reinterpret a missing inventory as a zero-argument list.
  WHEN ?3 IS NULL THEN 1
  ELSE EXISTS (
    SELECT 1 FROM json_each(?3) AS formal
    WHERE json_array_length(obligation.argument_slots,'$[0]')
        = formal.value->>0 + CASE WHEN site.site_kind=?5 AND site.namespace=?6
                                 THEN 0 ELSE formal.value->>1 END
  ) END
FROM temp.selected_resolution_mounts AS mount
LEFT JOIN resolution_sites AS site
  ON site.blob_id=mount.blob_id AND site.site=?2 AND site.role=0
LEFT JOIN resolution_semantic_sites AS reference
  ON reference.blob_id=site.blob_id AND reference.source_site=site.site
 AND reference.semantic_role='reference'
LEFT JOIN resolution_call_obligations AS obligation
  ON obligation.blob_id=reference.blob_id
 AND obligation.callee_reference=reference.semantic_key
LEFT JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=reference.blob_id AND context.semantic_key=reference.semantic_key
LEFT JOIN source_occurrence_arenas AS arena ON arena.blob_id=mount.blob_id
WHERE mount.storage_language='rust' AND mount.persisted_relative_path=?1
