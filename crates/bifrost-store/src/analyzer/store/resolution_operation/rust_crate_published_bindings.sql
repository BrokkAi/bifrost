-- One request over published own-binding rows, read from the unit-summary mirrors of the
-- selected unit (rust_resolution_unit_summary_binding_*). The selected-unit join is the
-- currency guard: a topology outside the current selection publishes nothing. Access is
-- checked at the binding.
WITH published_owners AS (
 SELECT unit.summary_id,owner.owner_handle,unit.topology_id,owner.module_path,owner.closed
 FROM selected_rust_unit_summaries unit
 CROSS JOIN rust_resolution_unit_summary_binding_owners owner INDEXED BY rust_summary_module_owner
  ON owner.summary_id=unit.summary_id
 WHERE owner.kind='module' AND unit.topology_id=?1
 AND (owner.module_path=?2 OR (?3='macro' AND ?2<>'crate' AND ?1=?5 AND owner.module_path='crate'))
), published_alternatives AS (
 SELECT alternative.* FROM published_owners owner
 CROSS JOIN rust_resolution_unit_summary_binding_alternatives alternative
  INDEXED BY rust_summary_alternatives_owner ON alternative.summary_id=owner.summary_id AND alternative.owner_handle=owner.owner_handle
 WHERE alternative.namespace=?3 AND alternative.name=?4 AND (alternative.visibility='public' OR (owner.topology_id=?5 AND (
 alternative.visibility='crate'
 OR (alternative.visibility='private' AND (?6=owner.module_path
     OR substr(?6,1,length(owner.module_path)+2)=owner.module_path || '::'))
 OR (alternative.visibility='restricted' AND (?6=alternative.restricted_module_path
     OR substr(?6,1,length(alternative.restricted_module_path)+2)=alternative.restricted_module_path || '::')))))
)
