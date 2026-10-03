SELECT json(naming.package_components), json(naming.root_components)
FROM rust_crate_file_naming AS naming
CROSS JOIN selected_rust_crates AS crates USING(topology_id)
WHERE naming.rel_path=?1
ORDER BY crates.target_kind <> 'lib', crates.crate_key LIMIT 1
