-- A certificate marker preserves a listed empty set without joining an alternatives CTE.
SELECT certificate.complete,NULL,NULL,NULL
FROM selected_rust_unit_summaries unit
CROSS JOIN rust_resolution_unit_summary_binding_owners owner INDEXED BY rust_summary_module_owner
 ON owner.summary_id=unit.summary_id
CROSS JOIN rust_resolution_unit_summary_binding_names certificate
 ON certificate.summary_id=owner.summary_id AND certificate.owner_handle=owner.owner_handle
WHERE owner.kind='module' AND unit.topology_id=?1 AND owner.module_path=?2
 AND certificate.namespace=?3 AND certificate.name=?4
UNION
SELECT certificate.complete,topology.topology_id,alternative.target_module_path,alternative.target_name
FROM published_alternatives alternative
CROSS JOIN rust_resolution_unit_summary_binding_owners owner
 ON owner.summary_id=alternative.summary_id AND owner.owner_handle=alternative.owner_handle
 AND owner.module_path=?2
CROSS JOIN rust_resolution_unit_summary_binding_names certificate
 ON certificate.summary_id=owner.summary_id AND certificate.owner_handle=owner.owner_handle
 AND certificate.namespace=alternative.namespace AND certificate.name=alternative.name
LEFT JOIN selected_rust_unit_summaries unit ON unit.unit_key=alternative.target_unit_key
LEFT JOIN rust_crate_topologies topology ON topology.topology_id=unit.topology_id
ORDER BY 1,2,3,4
