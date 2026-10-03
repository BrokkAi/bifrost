-- Visibility paths use the same module edges as imports. The source is the
-- producer's structured segments, never a parser over rendered Rust syntax.
WITH RECURSIVE routes(module_path, visibility, target_module_path, position) AS (
 SELECT module_path, visibility,
        CASE WHEN json_extract(cr_visibility_segments(visibility),'$[0]') IN ('self','super','crate')
             THEN module_path ELSE 'crate' END, 0
 FROM cr_restrictions
 UNION
 SELECT route.module_path, route.visibility,
        CASE WHEN segment.value='crate' AND route.position=0 THEN 'crate'
             WHEN segment.value='self' THEN route.target_module_path
             WHEN segment.value='super' THEN member.parent_module_path
             ELSE child.module_path END,
        route.position+1
 FROM routes AS route
 CROSS JOIN json_each(cr_visibility_segments(route.visibility)) AS segment ON segment.key=route.position
 LEFT JOIN cr_members AS member ON member.module_path=route.target_module_path AND member.placement<>'include'
 LEFT JOIN cr_members AS child ON child.module_path=route.target_module_path || '::' || segment.value
 WHERE route.position<64 AND ((segment.value='crate' AND route.position=0)
    OR segment.value='self' OR (segment.value='super' AND member.parent_module_path IS NOT NULL)
    OR child.module_path IS NOT NULL)
)
UPDATE cr_restrictions AS input SET restricted_module_path=route.target_module_path
FROM routes AS route
WHERE input.module_path=route.module_path AND input.visibility=route.visibility
 AND route.position=json_array_length(cr_visibility_segments(input.visibility))
 AND (input.module_path=route.target_module_path
      OR substr(input.module_path,1,length(route.target_module_path)+2)=route.target_module_path || '::');
