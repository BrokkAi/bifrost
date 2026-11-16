EXISTS(SELECT 1 FROM json_each('["type","value","macro"]') AS requested
               WHERE (?3='' OR requested.value=?3)
                 AND NOT EXISTS(
                  SELECT 1 FROM main.rust_resolution_unit_summary_binding_owners AS owner
                  CROSS JOIN main.rust_resolution_unit_summary_binding_alternatives AS explicit
                   ON explicit.summary_id=owner.summary_id AND explicit.owner_handle=owner.owner_handle
                  WHERE owner.summary_id=walk.summary_id AND owner.module_path=walk.module_path
                    AND owner.kind='module'
                    AND explicit.namespace=requested.value AND explicit.name=?4
                    AND explicit.origin<>'glob'))
 )
 SELECT gap.detail FROM walk
 CROSS JOIN temp.selected_rust_unplaced_gaps AS gap
  ON gap.summary_id=walk.summary_id AND gap.subject=walk.module_path
) AS reached
