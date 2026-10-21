-- A certificate marker preserves a listed empty set without joining an alternatives CTE.
SELECT certificate.complete,NULL,NULL,NULL
FROM rust_crate_binding_owners owner
JOIN rust_crate_binding_names certificate USING(owner_id)
WHERE owner.kind='module' AND owner.topology_id=?1 AND owner.module_path=?2
 AND certificate.namespace=?3 AND certificate.name=?4
UNION
SELECT certificate.complete,topology.topology_id,alternative.target_module_path,alternative.target_name
FROM published_alternatives alternative
CROSS JOIN rust_crate_binding_owners owner ON owner.owner_id=alternative.owner_id
 AND owner.module_path=?2
CROSS JOIN rust_crate_binding_names certificate ON certificate.owner_id=owner.owner_id
 AND certificate.namespace=alternative.namespace AND certificate.name=alternative.name
LEFT JOIN selected_rust_unit_summaries unit ON unit.unit_key=alternative.target_crate_key
LEFT JOIN rust_crate_topologies topology ON topology.topology_id=unit.topology_id
ORDER BY 1,2,3,4
