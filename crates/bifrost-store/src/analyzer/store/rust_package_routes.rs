//! Package-owned route evidence for targets that cannot publish a topology.
use super::*;
use std::collections::BTreeMap;

/// Request-local ownership. Healthy members come from the published module
/// walk; rejected targets run that same walk without publishing a topology.
#[derive(Default)]
pub(super) struct TargetMap {
    pub unavailable: Vec<PreparedCrate>,
    pub claims: BTreeMap<CrateKey, BTreeSet<PathBuf>>,
    pub manifests: BTreeMap<PathBuf, (i64, Oid)>,
    pub boundaries: BTreeSet<PathBuf>,
    pub owners: BTreeMap<CrateKey, PathBuf>,
    pub claimed_paths: BTreeSet<PathBuf>,
    pub configurations: BTreeMap<CrateKey, [u8; 32]>,
}

impl TargetMap {
    pub fn suppresses_detached(&self, path: &Path) -> bool {
        if self.claimed_paths.contains(path) {
            return true;
        }
        Self::admitted_by_package(
            path,
            &self.boundaries,
            self.unavailable
                .iter()
                .map(|unit| unit.target.manifest_path.as_path()),
        )
    }

    fn package_owner(path: &Path, boundaries: &BTreeSet<PathBuf>) -> Option<PathBuf> {
        path.parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .map(|directory| directory.join("Cargo.toml"))
            .find(|manifest| boundaries.contains(manifest))
    }

    fn admitted_by_package<'a>(
        path: &Path,
        boundaries: &BTreeSet<PathBuf>,
        mut unavailable: impl Iterator<Item = &'a Path>,
    ) -> bool {
        Self::package_owner(path, boundaries)
            .is_some_and(|owner| unavailable.any(|manifest| manifest == owner.as_path()))
    }

    // Lexical bounds only seek normalized directory paths in the sorted input.
    // Ownership itself always uses Path components and manifest boundaries.
    fn directory_bounds(directory: &Path) -> (String, Option<String>) {
        if directory.as_os_str().is_empty() {
            (String::new(), None)
        } else {
            let directory = stable_path(directory);
            (format!("{directory}/"), Some(format!("{directory}0")))
        }
    }

    fn directory_sources<'a>(
        sources: &'a [(String, String)],
        directory: &Path,
    ) -> &'a [(String, String)] {
        let (lower, upper) = Self::directory_bounds(directory);
        let start = sources.partition_point(|(path, _)| path < &lower);
        let end = upper.map_or(sources.len(), |upper| {
            sources.partition_point(|(path, _)| path < &upper)
        });
        &sources[start..end]
    }

    fn package_sources<'a>(
        sources: &'a [(String, String)],
        manifest: &'a Path,
        boundaries: &'a BTreeSet<PathBuf>,
    ) -> impl Iterator<Item = &'a (String, String)> {
        let mut remaining =
            Self::directory_sources(sources, manifest.parent().expect("manifest directory"));
        std::iter::from_fn(move || {
            loop {
                let first = remaining.first()?;
                let owner = Self::package_owner(Path::new(&first.0), boundaries)
                    .expect("the package manifest bounds its directory");
                if owner == manifest {
                    remaining = &remaining[1..];
                    return Some(first);
                }
                // Jump over a nested package's entire indexed directory, rather
                // than visiting its sources while processing the outer package.
                let skipped =
                    Self::directory_sources(remaining, owner.parent().expect("manifest directory"))
                        .len();
                assert!(skipped > 0, "a nested package owns the first source");
                remaining = &remaining[skipped..];
            }
        })
    }

    pub fn reseed_released_admissions(
        &self,
        source: &Connection,
        schedule: &Connection,
        snapshot: &WorkspaceSnapshotId,
        previous_revision: i64,
        sources: &[(String, String)],
    ) -> Result<()> {
        let mut previous: BTreeMap<PathBuf, BTreeSet<CrateKey>> = BTreeMap::new();
        let mut old = source.prepare_cached(
            "SELECT package.manifest_path,target.unit_key
             FROM rust_package_route_versions package
             JOIN rust_package_unavailable_targets target USING(route_set_id)
             WHERE package.workspace_id=?1 AND package.generation=?2
               AND package.derivation_identity=?4 AND package.valid_from<=?3
               AND (package.valid_until IS NULL OR ?3<package.valid_until)",
        )?;
        for row in old.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                previous_revision,
                derivation_identity()
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, CrateKey>(1)?)),
        )? {
            let (manifest, key) = row?;
            previous
                .entry(PathBuf::from(manifest))
                .or_default()
                .insert(key);
        }
        let mut current: BTreeMap<&Path, BTreeSet<CrateKey>> = BTreeMap::new();
        for unit in &self.unavailable {
            current
                .entry(&unit.target.manifest_path)
                .or_default()
                .insert(unit.key);
        }
        for (manifest, old_targets) in previous {
            if current.get(manifest.as_path()) == Some(&old_targets) {
                continue;
            }
            let directory = manifest.parent().expect("manifest directory");
            let (lower, upper) = Self::directory_bounds(directory);
            let mut boundaries = BTreeSet::from([manifest.clone()]);
            let mut selected = source.prepare_cached(
                "SELECT rel_path FROM workspace_file_versions
                 WHERE workspace_id=?1 AND lang='rust' AND generation=?2
                   AND input_kind='configuration' AND file_present=1
                   AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until)
                   AND rel_path>=?4 AND (?5 IS NULL OR rel_path<?5)",
            )?;
            for path in selected.query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    previous_revision,
                    lower,
                    upper
                ],
                |row| row.get::<_, String>(0),
            )? {
                let path = PathBuf::from(path?);
                if path.starts_with(directory)
                    && path.file_name().is_some_and(|name| name == "Cargo.toml")
                {
                    boundaries.insert(path);
                }
            }
            let released = Self::package_sources(sources, &manifest, &boundaries)
                .filter(|(path, _)| {
                    Self::admitted_by_package(
                        Path::new(path),
                        &boundaries,
                        std::iter::once(manifest.as_path()),
                    ) && !self.suppresses_detached(Path::new(path))
                })
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            schedule.prepare_cached("INSERT OR IGNORE INTO temp.rust_schedule_paths SELECT value FROM json_each(?1)")?.execute([serde_json::to_string(&released).expect("source paths serialize")],
            )?;
        }
        Ok(())
    }

    pub fn publish(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        sources: &[(String, String)],
    ) -> Result<()> {
        // Same-revision retries withdraw their attempt; older and future
        // selections keep nonoverlapping intervals.
        conn.prepare_cached("DELETE FROM rust_package_route_versions WHERE workspace_id=?1 AND generation=?2 AND valid_from=?3")?.execute(params![snapshot.workspace_id.as_str(),snapshot.generation.0,snapshot.revision])?;
        let mut claims_by_package: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (unit, paths) in &self.claims {
            if let Some(manifest) = self.owners.get(unit) {
                claims_by_package
                    .entry(manifest)
                    .or_default()
                    .push((unit, paths));
            }
        }
        let mut unavailable_by_package: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for unit in &self.unavailable {
            unavailable_by_package
                .entry(&unit.target.manifest_path)
                .or_default()
                .push(unit);
        }
        let mut configurations_by_package: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (unit, owner) in &self.owners {
            configurations_by_package
                .entry(owner)
                .or_default()
                .push((unit, &self.configurations[unit]));
        }
        for (manifest, (version, manifest_oid)) in &self.manifests {
            let units = unavailable_by_package
                .get(manifest)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let claims = claims_by_package
                .get(manifest)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut output = Sha256::new();
            hash_cell(&mut output, b"rust-package-route-output:v2");
            hash_cell(&mut output, manifest_oid.as_bytes());
            for unit in units {
                let gap = unit
                    .target
                    .root_unavailable
                    .as_ref()
                    .expect("unavailable target");
                hash_cell(&mut output, &unit.key);
                hash_cell(&mut output, target_kind(unit.target.kind).as_bytes());
                hash_cell(&mut output, unit.target.name.as_bytes());
                hash_cell(&mut output, self.configurations[&unit.key].as_slice());
                hash_cell(&mut output, &[u8::from(gap.normalized_root.is_some())]);
                if let Some(root) = &gap.normalized_root {
                    hash_cell(&mut output, stable_path(root).as_bytes());
                }
                hash_cell(&mut output, gap.reason.label().as_bytes());
                hash_cell(&mut output, stable_path(&gap.declared_root).as_bytes());
            }
            for (unit, paths) in claims {
                hash_cell(&mut output, unit.as_slice());
                for path in *paths {
                    hash_cell(&mut output, stable_path(path).as_bytes());
                }
            }
            let output_digest: [u8; 32] = output.finalize().into();
            let manifest_path = stable_path(manifest);
            // Equal value and manifest binding carry the existing interval.
            // Its input digest names the creator inputs; the current reconcile
            // marker certifies that the same value still holds at this revision.
            let unchanged:bool=conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM rust_package_route_versions WHERE workspace_id=?1 AND generation=?2 AND manifest_path=?3 AND manifest_file_version_id=?4 AND derivation_identity=?5 AND output_digest=?6 AND valid_from<=?7 AND (valid_until IS NULL OR ?7<valid_until))")?.query_row(params![snapshot.workspace_id.as_str(),snapshot.generation.0,manifest_path,version,derivation_identity(),output_digest.as_slice(),snapshot.revision],|row|row.get(0))?;
            if unchanged {
                continue;
            }
            let mut inputs = Sha256::new();
            hash_cell(&mut inputs, b"rust-package-route-input:v2");
            hash_cell(&mut inputs, &derivation_identity());
            hash_cell(&mut inputs, manifest_oid.as_bytes());
            for (path, oid) in Self::package_sources(sources, manifest, &self.boundaries) {
                hash_cell(&mut inputs, path.as_bytes());
                hash_cell(&mut inputs, oid.as_bytes());
            }
            for (unit, configuration) in configurations_by_package
                .get(manifest)
                .into_iter()
                .flatten()
            {
                hash_cell(&mut inputs, unit.as_slice());
                hash_cell(&mut inputs, configuration.as_slice());
            }
            for (unit, paths) in claims {
                hash_cell(&mut inputs, unit.as_slice());
                for path in *paths {
                    let path = stable_path(path);
                    hash_cell(&mut inputs, path.as_bytes());
                    match sources.binary_search_by(|(selected, _)| selected.cmp(&path)) {
                        Ok(position) => {
                            hash_cell(&mut inputs, b"present");
                            hash_cell(&mut inputs, sources[position].1.as_bytes());
                        }
                        Err(_) => hash_cell(&mut inputs, b"absent"),
                    }
                }
            }
            let input_digest: [u8; 32] = inputs.finalize().into();
            conn.prepare_cached("UPDATE rust_package_route_versions SET valid_until=?4 WHERE workspace_id=?1 AND generation=?2 AND manifest_path=?3 AND valid_from<?4 AND (valid_until IS NULL OR ?4<valid_until)")?.execute(params![snapshot.workspace_id.as_str(),snapshot.generation.0,manifest_path,snapshot.revision])?;
            conn.prepare_cached("INSERT INTO rust_package_route_versions(workspace_id,generation,manifest_path,manifest_file_version_id,valid_from,valid_until,derivation_identity,input_digest,output_digest) VALUES(?1,?2,?3,?4,?5,(SELECT min(valid_from) FROM rust_package_route_versions WHERE workspace_id=?1 AND generation=?2 AND manifest_path=?3 AND valid_from>?5),?6,?7,?8)")?.execute(params![snapshot.workspace_id.as_str(),snapshot.generation.0,manifest_path,version,snapshot.revision,derivation_identity(),input_digest.as_slice(),output_digest.as_slice()])?;
            let id = conn.last_insert_rowid();
            for unit in units {
                let gap = unit
                    .target
                    .root_unavailable
                    .as_ref()
                    .expect("unavailable target");
                conn.prepare_cached(
                    "INSERT INTO rust_package_unavailable_targets VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                )?
                .execute(params![
                    id,
                    unit.key.as_slice(),
                    target_kind(unit.target.kind),
                    unit.target.name,
                    stable_path(&gap.declared_root),
                    gap.normalized_root.as_deref().map(stable_path),
                    self.configurations[&unit.key].as_slice(),
                    gap.reason.label()
                ])?;
            }
            for (unit, paths) in claims {
                for path in *paths {
                    conn.prepare_cached("INSERT INTO rust_package_target_claims VALUES(?1,?2,?3)")?
                        .execute(params![id, unit.as_slice(), stable_path(path)])?;
                }
            }
        }
        let manifests = serde_json::to_string(
            &self
                .manifests
                .keys()
                .map(|path| stable_path(path))
                .collect::<Vec<_>>(),
        )
        .expect("manifest paths serialize");
        conn.prepare_cached("UPDATE rust_package_route_versions SET valid_until=?3 WHERE workspace_id=?1 AND generation=?2 AND valid_from<?3 AND (valid_until IS NULL OR ?3<valid_until) AND manifest_path NOT IN (SELECT value FROM json_each(?4))")?.execute(params![snapshot.workspace_id.as_str(),snapshot.generation.0,snapshot.revision,manifests])?;
        Ok(())
    }
}
