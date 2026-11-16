-- Whether an impl whose members would be children of the asked declaration cannot
-- be attributed to it, so that rust_impl_children.sql cannot return its children.
-- Same parameters as that statement (?1..?9); one row, 1 when children may be missing:
--   a trait impl whose subject endpoint the summary left unresolved under the
--   asked declaration's name although a route bound it (the target had no live
--   summary when the impl's unit was derived), because an unresolved endpoint
--   carries only a spelling;
--   an unresolved subject ('unbound_incomplete' or 'ambiguous') in a selected
--   unit that is or transitively depends on the asked declaration's unit. An open
--   route can hide a rename, so spelling cannot exclude the asked declaration;
--   a foreign-form inherent impl whose name form several declaration exports carry;
--   any unresolved inherent impl in the asked declaration's selected unit. Rust
--   requires inherent impls in the self type's crate; other crates cannot hide
--   these children. An open route can hide a rename, so no spelling filter applies.
-- An 'unbound_external' subject has a positive absence certificate and is not a gap.
-- Trait halves never hide children: the resolved subject attributes every member.
-- Every arm seeks a selected summary's rows, never a unit's whole table.
WITH {subjects}
SELECT
 EXISTS(
  SELECT 1 FROM subjects
  CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS subject
    INDEXED BY rust_resolution_unit_summary_trait_endpoints_target
    ON subject.target_unit_key=subjects.unit_key
   AND subject.target_module_path=subjects.module_path
   AND subject.target_identity_id=subjects.identity_id
   AND subject.endpoint_role='subject' AND subject.endpoint_state='resolved'
  CROSS JOIN selected_rust_unit_summaries AS impl_unit ON impl_unit.summary_id=subject.summary_id
  WHERE (SELECT count(*) FROM rust_resolution_unit_summary_exports AS same_name
        INDEXED BY rust_summary_decl_export_endpoint
        WHERE same_name.summary_id=subjects.summary_id
          AND same_name.module_path=subjects.module_path
          AND same_name.namespace='type' AND same_name.name=subjects.name
          AND same_name.origin='declaration')>1
 ) OR EXISTS(
  SELECT 1 FROM subjects
  CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS unresolved
    INDEXED BY rust_resolution_unit_summary_trait_endpoints_unresolved
    ON unresolved.endpoint_role='subject' AND unresolved.endpoint_state='unresolved'
   AND unresolved.unresolved_spelling=subjects.name
   AND unresolved.unresolved_reason='bound_without_declaration'
  CROSS JOIN selected_rust_unit_summaries AS impl_unit ON impl_unit.summary_id=unresolved.summary_id
 ) OR EXISTS(
  SELECT 1 FROM subjects
  CROSS JOIN selected_rust_unit_closure AS reach
    INDEXED BY selected_rust_unit_closure_dependents
    ON reach.summary_id=subjects.summary_id
  CROSS JOIN selected_rust_unit_summaries AS impl_unit
    INDEXED BY selected_rust_unit_summaries_key
    ON impl_unit.unit_key=reach.root_unit_key
  CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS unresolved
    INDEXED BY rust_resolution_unit_summary_trait_endpoints_impl
    ON unresolved.summary_id=impl_unit.summary_id
   AND unresolved.endpoint_role='subject' AND unresolved.endpoint_state='unresolved'
   AND unresolved.unresolved_reason IN ('unbound_incomplete','ambiguous')
 ) OR EXISTS(
  SELECT 1 FROM subjects
  CROSS JOIN rust_resolution_unit_summary_inherent_impls AS inherent
    INDEXED BY rust_summary_inherent_subject
    ON inherent.subject_unit_key=subjects.unit_key
   AND inherent.subject_module_path=subjects.module_path
   AND inherent.subject_kind='declaration' AND inherent.subject_namespace='type'
   AND inherent.subject_name=subjects.name AND inherent.subject_origin='declaration'
   AND inherent.subject_form='foreign'
  CROSS JOIN selected_rust_unit_summaries AS impl_unit ON impl_unit.summary_id=inherent.summary_id
  WHERE (SELECT count(*) FROM rust_resolution_unit_summary_exports AS same_name
         INDEXED BY rust_summary_decl_export_endpoint
         WHERE same_name.summary_id=subjects.summary_id
           AND same_name.module_path=subjects.module_path
           AND same_name.namespace='type' AND same_name.name=subjects.name
           AND same_name.origin='declaration')>1
 )
 OR EXISTS(
  SELECT 1 FROM subjects
  CROSS JOIN rust_resolution_unit_summary_unresolved_inherent_impls AS unresolved_inherent
    ON unresolved_inherent.summary_id=subjects.summary_id
 )
