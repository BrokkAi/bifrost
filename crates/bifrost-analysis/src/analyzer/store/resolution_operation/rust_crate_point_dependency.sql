SELECT target.topology_id FROM rust_crate_dependencies AS dependency
CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
WHERE dependency.topology_id=?1 AND dependency.extern_name=?2
UNION
SELECT target.topology_id FROM rust_crate_container_sources AS root
CROSS JOIN source_rust_import_targets AS import ON import.blob_id=root.blob_id
CROSS JOIN rust_crate_dependencies AS dependency ON dependency.topology_id=root.topology_id AND dependency.extern_name=import.imported_name
CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
WHERE root.topology_id=?1 AND root.container_path='crate'
 AND import.is_extern_crate=1 AND import.bound_name=?2
 AND import.local_start IS NULL AND COALESCE(import.owner_module,'')=''
