-- One request over published own-binding rows. Access is checked at the binding.
WITH published_owners AS (
 SELECT owner_id,topology_id,module_path,closed FROM rust_crate_binding_owners
 WHERE kind='module' AND topology_id=?1
 AND (module_path=?2 OR (?3='macro' AND ?2<>'crate' AND ?1=?5 AND module_path='crate'))
), published_alternatives AS (
 SELECT alternative.* FROM published_owners owner
 JOIN rust_crate_binding_alternatives alternative USING(owner_id)
 WHERE alternative.namespace=?3 AND alternative.name=?4 AND (alternative.visibility='public' OR (owner.topology_id=?5 AND (
 alternative.visibility='crate'
 OR (alternative.visibility='private' AND (?6=owner.module_path
     OR substr(?6,1,length(owner.module_path)+2)=owner.module_path || '::'))
 OR (alternative.visibility='restricted' AND (?6=alternative.restricted_module_path
     OR substr(?6,1,length(alternative.restricted_module_path)+2)=alternative.restricted_module_path || '::')))))
)
