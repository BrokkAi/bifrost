, targets(topology_id,module_path,name,followed) AS (
 SELECT ?1,?2,?4,0
 UNION
 SELECT topology.topology_id,alternative.target_module_path,alternative.target_name,1
 FROM published_alternatives alternative
 JOIN selected_rust_unit_summaries unit ON unit.unit_key=alternative.target_crate_key
 JOIN rust_crate_topologies topology ON topology.topology_id=unit.topology_id
 UNION
 SELECT endpoint.topology_id,alternative.target_module_path,alternative.target_name,1
 FROM macro_prelude_owners AS provider
 CROSS JOIN rust_crate_binding_alternatives AS alternative
  ON alternative.owner_id=provider.owner_id AND alternative.namespace='macro'
 AND alternative.name=?4 AND alternative.visibility='public'
 CROSS JOIN selected_rust_unit_summaries AS endpoint
  ON endpoint.unit_key=alternative.target_crate_key
)

