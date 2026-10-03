-- One module route walk, shared by `use` paths and by qualified root
-- references. A step keeps the current crate while the segment names one of
-- its containers, enters a dependency at an extern name, and follows a
-- re-export route when the segment names a container another crate published
-- and this one re-exported. Same-crate and cross-crate steps are the same
-- statement over `cr_containers_all` and `cr_reexport_closure`, which carry
-- this crate's pending temp rows and every already-derived crate's published
-- rows under one crate key; the closure is the re-export chain already chased
-- to the container it ends on. A real container always beats a re-export of
-- the same name, which is why the re-export join carries the container test.
-- A glob import binds every name its target module publishes, so a segment
-- that is neither a container nor a named re-export can still name a module
-- reached through `use other::*;`. `cr_glob_closure` is the glob-edge
-- transitive closure, so a chain of globs (`use crate::*;` over
-- `pub use a::*;` over `pub use b::*;`) is one join. Glob binding is the
-- weakest form, so its join carries the same container test the re-export
-- join carries and its CASE arms sit below the dependency and re-export arms.
WITH RECURSIVE routes(blob_id, {key}, module_path, target_crate_key,
                      target_module_path, position) AS (
  SELECT source.blob_id, source.{key}, source.module_path, ?1,
         CASE WHEN ?2 = '2015' AND NOT EXISTS (
                SELECT 1 FROM {segments} AS first
                WHERE first.blob_id=source.blob_id AND first.{key}=source.{key}
                  AND first.ordinal=0 AND first.segment IN ('self', 'super', 'crate'))
              THEN 'crate' ELSE source.module_path END, 0
  FROM {sources} AS source
  UNION ALL
  SELECT route.blob_id, route.{key}, route.module_path,
         CASE WHEN dependency.dependency_crate_key IS NOT NULL THEN dependency.dependency_crate_key
              WHEN reexport.target_crate_key IS NOT NULL THEN reexport.target_crate_key
              WHEN glob_reexport.target_crate_key IS NOT NULL THEN glob_reexport.target_crate_key
              WHEN globbed.target_crate_key IS NOT NULL THEN globbed.target_crate_key
              ELSE route.target_crate_key END,
         CASE WHEN segment.segment = 'crate' AND route.position = 0 THEN 'crate'
              WHEN segment.segment = 'self' THEN route.target_module_path
              WHEN segment.segment = 'super' THEN member.parent_module_path
              WHEN dependency.dependency_crate_key IS NOT NULL THEN 'crate'
              WHEN reexport.target_container_path IS NOT NULL THEN reexport.target_container_path
              WHEN glob_reexport.target_container_path IS NOT NULL THEN glob_reexport.target_container_path
              WHEN globbed.target_module_path IS NOT NULL
                THEN globbed.target_module_path || '::' || segment.segment
              ELSE route.target_module_path || '::' || segment.segment END,
         route.position + 1
  FROM routes AS route
  JOIN {segments} AS segment
    ON segment.blob_id = route.blob_id AND segment.{key} = route.{key}
   AND segment.ordinal = route.position
  LEFT JOIN cr_dependencies AS dependency ON route.position = 0
    AND dependency.extern_name = segment.segment
  LEFT JOIN cr_members AS member ON route.target_crate_key = ?1
    AND member.module_path = route.target_module_path AND member.placement <> 'include'
  LEFT JOIN cr_reexport_closure AS reexport
    ON reexport.crate_key = route.target_crate_key
   AND reexport.module_path = route.target_module_path
   AND reexport.bound_name = segment.segment
   AND NOT EXISTS(SELECT 1 FROM cr_containers_all AS child
                  WHERE child.crate_key = route.target_crate_key
                    AND child.container_path = route.target_module_path || '::' || segment.segment)
  LEFT JOIN cr_glob_closure AS globbed
    ON globbed.crate_key = route.target_crate_key
   AND globbed.module_path = route.target_module_path
   AND NOT EXISTS(SELECT 1 FROM cr_containers_all AS child
                  WHERE child.crate_key = route.target_crate_key
                    AND child.container_path = route.target_module_path || '::' || segment.segment)
   AND (EXISTS(SELECT 1 FROM cr_containers_all AS glob_child
               WHERE glob_child.crate_key = globbed.target_crate_key
                 AND glob_child.container_path
                     = globbed.target_module_path || '::' || segment.segment)
        OR EXISTS(SELECT 1 FROM cr_reexport_closure AS exported
                  WHERE exported.crate_key = globbed.target_crate_key
                    AND exported.module_path = globbed.target_module_path
                    AND exported.bound_name = segment.segment))
  -- A glob can import a namespace that the reached module re-exports,
  -- including a dependency's root. Its destination is the re-export's
  -- canonical container, not a synthetic child of the globbed module.
  LEFT JOIN cr_reexport_closure AS glob_reexport
    ON glob_reexport.crate_key = globbed.target_crate_key
   AND glob_reexport.module_path = globbed.target_module_path
   AND glob_reexport.bound_name = segment.segment
   AND NOT EXISTS(SELECT 1 FROM cr_containers_all AS glob_child
                  WHERE glob_child.crate_key = globbed.target_crate_key
                    AND glob_child.container_path
                        = globbed.target_module_path || '::' || segment.segment)
  WHERE (segment.segment = 'crate' AND route.position = 0)
     OR segment.segment = 'self'
     OR (segment.segment = 'super' AND member.parent_module_path IS NOT NULL)
     OR dependency.dependency_crate_key IS NOT NULL
     OR reexport.target_crate_key IS NOT NULL
     OR globbed.target_crate_key IS NOT NULL
     OR route.target_crate_key <> ?1
     OR EXISTS(SELECT 1 FROM cr_containers_all AS child
               WHERE child.crate_key = route.target_crate_key
                 AND child.container_path = route.target_module_path || '::' || segment.segment)
     OR EXISTS(SELECT 1 FROM cr_members AS parent
               CROSS JOIN source_rust_module_declarations AS declaration
                 ON declaration.blob_id=parent.blob_id AND declaration.module_name=segment.segment
               WHERE parent.module_path=route.target_module_path)
)
INSERT OR IGNORE INTO {output}
SELECT route.blob_id, route.{key}, route.module_path,
       route.target_crate_key, route.target_module_path
FROM routes AS route
WHERE NOT EXISTS(SELECT 1 FROM {segments} AS segment
                 WHERE segment.blob_id = route.blob_id
                   AND segment.{key} = route.{key}
                   AND segment.ordinal = route.position);
