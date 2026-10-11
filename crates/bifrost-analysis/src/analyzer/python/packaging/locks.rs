//! Exact candidates from explicitly supported static lock schemas.
use super::*;

/// Associate direct Poetry requirements only after the caller establishes the
/// manifest/lock pairing. Both inputs must come from the same acquisition.
/// Unassociated candidates remain separate; this does not resolve a lock or
/// activate an environment. The declaration and source reference prove the
/// relation, rather than a package name or workspace co-occurrence alone.
pub fn associate_python_poetry_lock(
    declarations: &DependencyFileEvidence,
    lock: &mut DependencyFileEvidence,
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) {
    let projects = declarations
        .rows
        .iter()
        .filter(|row| {
            row.kind == Kind::Declared && row.conditions.contains(&condition("role", "project"))
        })
        .collect::<Vec<_>>();
    let [project] = projects.as_slice() else {
        if let Some(row) = lock.rows.first() {
            let path = row.build_file.clone();
            push_gap(
                lock,
                &path,
                0..0,
                Gap::Unresolved,
                "Poetry association requires one established project declaration",
            );
        }
        return;
    };
    let Some(owner) = &project.declared_by else {
        return;
    };
    let mut associated = DependencyFileEvidence::default();
    let mut work = 0usize;
    for declaration in &declarations.rows {
        if declaration.kind != Kind::Declared
            || declaration
                .conditions
                .contains(&condition("role", "project"))
            || !declaration.complete
            || declaration.declared_by.as_ref() != Some(owner)
            || declaration
                .conditions
                .iter()
                .any(|condition| condition.kind == "source_selection")
        {
            continue;
        }
        let mut matched = false;
        for candidate in &lock.rows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) || work >= limits.max_rows
            {
                push_gap(
                    &mut associated,
                    &declaration.build_file,
                    declaration.byte_range.clone(),
                    if cancellation.is_some_and(CancellationToken::is_cancelled) {
                        Gap::Cancelled
                    } else {
                        Gap::Limit
                    },
                    "Poetry association work budget exhausted or cancelled",
                );
                append_bounded_evidence(lock, &mut associated, &project.build_file, limits);
                return;
            }
            work += 1;
            if candidate.kind != Kind::Locked
                || candidate.declared_by.is_some()
                || !candidate
                    .locator
                    .as_deref()
                    .is_some_and(|locator| locator.starts_with("poetry:package["))
                || candidate.build_file.parent() != project.build_file.parent()
                || candidate.package != declaration.package
                || !poetry_sources_agree(declaration.source.as_deref(), candidate.source.as_deref())
                || python_evidence_matches_version(
                    candidate,
                    declaration.version_requirement.as_deref().unwrap_or(""),
                ) != Some(true)
            {
                continue;
            }
            let mut row = candidate.clone();
            row.declared_by = Some(owner.clone());
            row.scope = declaration.scope;
            row.conditions
                .extend(declaration.conditions.iter().cloned());
            row.conditions.extend(
                project
                    .conditions
                    .iter()
                    .filter(|condition| condition.kind == "requires_python")
                    .cloned(),
            );
            row.conditions.push(condition(
                "declaration_file",
                &declaration.build_file.to_string_lossy().replace('\\', "/"),
            ));
            row.conditions.push(condition(
                "declaration_snapshot",
                &declaration.source_digest,
            ));
            row.conditions.push(condition(
                "declaration_range",
                &format!(
                    "{}:{}",
                    declaration.byte_range.start, declaration.byte_range.end
                ),
            ));
            associated.rows.push(row);
            matched = true;
        }
        if !matched {
            push_gap(
                &mut associated,
                &declaration.build_file,
                declaration.byte_range.clone(),
                Gap::Unresolved,
                &format!(
                    "no supported Poetry candidate proves direct requirement/source association for {}",
                    declaration.package
                ),
            );
        }
    }
    append_bounded_evidence(lock, &mut associated, &project.build_file, limits);
}

fn poetry_sources_agree(declared: Option<&str>, locked: Option<&str>) -> bool {
    let Some(declared) = declared else {
        return locked == Some("registry:pypi");
    };
    let Some(locked) = locked else {
        return false;
    };
    let Ok(locked) = serde_json::from_str::<serde_json::Value>(locked) else {
        return false;
    };
    let Ok(declared_json) = serde_json::from_str::<serde_json::Value>(declared) else {
        return locked.get("type").and_then(serde_json::Value::as_str) == Some("url")
            && locked.get("url").and_then(serde_json::Value::as_str) == Some(declared);
    };
    let declared = declared_json;
    match locked.get("type").and_then(serde_json::Value::as_str) {
        Some("url") => declared.get("url").is_some() && declared.get("url") == locked.get("url"),
        Some("directory" | "file") => {
            declared.get("path").is_some() && declared.get("path") == locked.get("url")
        }
        Some("git") => {
            declared.get("git").is_some()
                && declared.get("git") == locked.get("url")
                && ["branch", "tag", "rev"].iter().all(|key| {
                    declared
                        .get(*key)
                        .is_none_or(|reference| Some(reference) == locked.get("reference"))
                })
        }
        // A configured index name is not a full source identity. Its URL and
        // selection need source-table binding; matching labels cannot prove it.
        Some("legacy") => false,
        _ => false,
    }
}

impl Reader<'_> {
    pub(super) fn uv_lock(&mut self, document: &Item) {
        if document.get("version").and_then(Item::as_integer) != Some(1)
            || document
                .get("revision")
                .is_some_and(|revision| !matches!(revision.as_integer(), Some(1..=3)))
        {
            self.gap(
                0..self.source.len(),
                Gap::Unsupported,
                "supported uv lock schema is version 1, revisions 1 through 3",
            );
            return;
        }
        let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) else {
            self.gap(
                0..self.source.len(),
                Gap::Malformed,
                "uv lock needs package tables",
            );
            return;
        };
        let mut context = Vec::new();
        if let Some(requires) = document.get("requires-python") {
            match requires
                .as_str()
                .and_then(|raw| VersionSpecifiers::from_str(raw).ok())
            {
                Some(requires) => context.push(condition("requires_python", &requires.to_string())),
                None => self.gap(
                    requires.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid lock requires-python",
                ),
            }
        }
        for key in [
            "resolution-markers",
            "environments",
            "supported-environments",
        ] {
            if let Some(values) = document.get(key) {
                self.lock_markers(values, key, &mut context);
            }
        }
        for (index, package) in packages.iter().enumerate() {
            if self.stopped() {
                break;
            }
            let range = package.span().unwrap_or(0..0);
            let Some(name) = package
                .get("name")
                .and_then(Item::as_str)
                .and_then(|name| PackageName::from_str(name).ok())
            else {
                self.gap(
                    range,
                    Gap::Malformed,
                    "lock package has invalid/missing distribution name",
                );
                continue;
            };
            let mut row = self.row(
                name.to_string(),
                Kind::Locked,
                range,
                DependencyScope::Unknown,
            );
            row.declared_by = None;
            row.locator = Some(format!("uv:package[{index}]"));
            row.conditions.extend(context.iter().cloned());
            self.exact_lock_version(package.get("version"), &mut row);
            match package.get("source") {
                Some(source) => match uv_source_identity(source) {
                    Some(source) => row.source = Some(source),
                    None => {
                        row.complete = false;
                        self.gap(
                            row.byte_range.clone(),
                            Gap::Malformed,
                            "invalid uv package source",
                        );
                    }
                },
                None => {
                    row.complete = false;
                    self.gap(
                        row.byte_range.clone(),
                        Gap::Malformed,
                        "uv package source is missing",
                    );
                }
            }
            if let Some(markers) = package.get("resolution-markers") {
                self.lock_markers(markers, "candidate_resolution_marker", &mut row.conditions);
            }
            // Keep references as relationships in the acquisition fact. An
            // unselected fork does not establish project or runtime ownership.
            for key in ["dependencies", "optional-dependencies", "dev-dependencies"] {
                if let Some(item) = package.get(key) {
                    row.conditions.push(condition(key, &item.to_string()));
                }
            }
            self.output.rows.push(row);
        }
        self.uv_direct_owners(packages);
    }

    fn uv_direct_owners(&mut self, packages: &toml_edit::ArrayOfTables) {
        for package in packages {
            if self.stopped() {
                break;
            }
            let Some(source) = package.get("source").and_then(Item::as_table_like) else {
                continue;
            };
            let Some(local) = ["editable", "virtual", "directory"]
                .into_iter()
                .find_map(|key| source.get(key).and_then(Item::as_str))
            else {
                continue;
            };
            if !safe_relative_path(Path::new(local)) {
                self.gap(
                    package.span().unwrap_or(0..0),
                    Gap::UnsafePath,
                    "local uv project path is unsafe",
                );
                continue;
            }
            let Some(name) = package
                .get("name")
                .and_then(Item::as_str)
                .and_then(|name| PackageName::from_str(name).ok())
            else {
                continue;
            };
            let manifest = self
                .path
                .parent()
                .unwrap_or(Path::new(""))
                .join(local)
                .join("pyproject.toml");
            use brokk_bifrost_core::path_normalization::NormalizePath;
            let manifest = manifest.normalize();
            let owner = python_project_entity(&manifest, name.as_ref()).id();
            if let Some(dependencies) = package.get("dependencies") {
                self.uv_references(dependencies, &owner, DependencyScope::Runtime, &[]);
            }
            for (key, label, scope) in [
                ("optional-dependencies", "extra", DependencyScope::Optional),
                ("dev-dependencies", "group", DependencyScope::FeatureGated),
            ] {
                if let Some(groups) = package.get(key) {
                    if let Some(table) = groups.as_table_like() {
                        for (name, references) in table.iter() {
                            self.uv_references(
                                references,
                                &owner,
                                scope,
                                &[condition(label, name)],
                            );
                        }
                    } else {
                        self.gap(
                            groups.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "uv dependency groups must be tables",
                        );
                    }
                }
            }
        }
    }

    fn uv_references(
        &mut self,
        references: &Item,
        owner: &str,
        scope: DependencyScope,
        conditions: &[DependencyCondition],
    ) {
        let Some(array) = references.as_array() else {
            self.gap(
                references.span().unwrap_or(0..0),
                Gap::Malformed,
                "uv dependency references must be arrays",
            );
            return;
        };
        for reference in array {
            if self.stopped() {
                break;
            }
            let Some(table) = reference.as_inline_table() else {
                self.gap(
                    reference.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "uv dependency reference must be a table",
                );
                continue;
            };
            let Some(name) = table
                .get("name")
                .and_then(Value::as_str)
                .and_then(|name| PackageName::from_str(name).ok())
            else {
                self.gap(
                    reference.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid uv dependency reference name",
                );
                continue;
            };
            let source = table
                .get("source")
                .and_then(|value| uv_source_identity(&Item::Value(value.clone())));
            let version = table
                .get("version")
                .and_then(Value::as_str)
                .and_then(|version| Version::from_str(version).ok())
                .map(|version| version.to_string());
            if (table.get("source").is_some() && source.is_none())
                || (table.get("version").is_some() && version.is_none())
            {
                self.gap(
                    reference.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid uv reference version/source",
                );
                continue;
            }
            self.lock_reference_work = self
                .lock_reference_work
                .saturating_add(self.output.rows.len());
            if self.lock_reference_work > self.limits.max_rows {
                self.gap(
                    reference.span().unwrap_or(0..0),
                    Gap::Limit,
                    "lock association scan budget exhausted",
                );
                return;
            }
            let candidates = self
                .output
                .rows
                .iter()
                .filter(|row| {
                    row.kind == Kind::Locked
                        && row.declared_by.is_none()
                        && row.package == name.as_ref()
                        && version
                            .as_ref()
                            .is_none_or(|version| row.exact_version.as_ref() == Some(version))
                        && source
                            .as_ref()
                            .is_none_or(|source| row.source.as_ref() == Some(source))
                })
                .cloned()
                .collect::<Vec<_>>();
            // The lock may explicitly reference a fork set. Keep every fork
            // separately with its candidate-specific conditions. This does
            // not choose one for a host platform.
            if candidates.is_empty() {
                self.gap(
                    reference.span().unwrap_or(0..0),
                    Gap::Unresolved,
                    "uv dependency reference has no matching lock candidate",
                );
            }
            for mut candidate in candidates {
                if self.stopped() {
                    break;
                }
                candidate.declared_by = Some(owner.to_owned());
                candidate.scope = scope;
                candidate.conditions.extend_from_slice(conditions);
                if let Some(marker) = table.get("marker") {
                    match marker
                        .as_str()
                        .and_then(|marker| pep508_rs::MarkerTree::from_str(marker).ok())
                    {
                        Some(marker) => {
                            if let Some(contents) = marker.contents() {
                                candidate
                                    .conditions
                                    .push(condition("marker", &contents.to_string()));
                            }
                        }
                        None => {
                            candidate.complete = false;
                            self.gap(
                                reference.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "invalid uv dependency marker",
                            );
                        }
                    }
                }
                if let Some(extras) = table.get("extra").or_else(|| table.get("extras")) {
                    candidate
                        .conditions
                        .push(condition("requested_extra", &extras.to_string()));
                }
                candidate.conditions.push(condition(
                    "association_range",
                    &format!(
                        "{}:{}",
                        reference.span().unwrap_or(0..0).start,
                        reference.span().unwrap_or(0..0).end
                    ),
                ));
                self.output.rows.push(candidate);
            }
        }
    }

    pub(super) fn poetry_lock(&mut self, document: &Item) {
        let schema = document
            .get("metadata")
            .and_then(|metadata| metadata.get("lock-version"))
            .and_then(Item::as_str);
        if !matches!(schema, Some("1.1" | "2.0" | "2.1")) {
            self.gap(
                0..self.source.len(),
                Gap::Unsupported,
                "supported Poetry lock versions are 1.1, 2.0 and 2.1",
            );
            return;
        }
        let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) else {
            self.gap(
                0..self.source.len(),
                Gap::Malformed,
                "Poetry lock needs package tables",
            );
            return;
        };
        for (index, package) in packages.iter().enumerate() {
            if self.stopped() {
                break;
            }
            let Some(name) = package
                .get("name")
                .and_then(Item::as_str)
                .and_then(|name| PackageName::from_str(name).ok())
            else {
                self.gap(
                    package.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid Poetry lock package name",
                );
                continue;
            };
            let mut row = self.row(
                name.to_string(),
                Kind::Locked,
                package.span().unwrap_or(0..0),
                DependencyScope::Unknown,
            );
            row.declared_by = None;
            row.locator = Some(format!("poetry:package[{index}]"));
            self.exact_lock_version(package.get("version"), &mut row);
            row.source = match package.get("source") {
                Some(source) => source_identity(
                    source,
                    &[
                        "type",
                        "url",
                        "reference",
                        "resolved_reference",
                        "subdirectory",
                    ],
                )
                .filter(|_| {
                    source.get("type").and_then(Item::as_str).is_some()
                        && source.get("url").and_then(Item::as_str).is_some()
                }),
                None => Some("registry:pypi".to_owned()),
            };
            if row.source.is_none() {
                row.complete = false;
                self.gap(
                    row.byte_range.clone(),
                    Gap::Malformed,
                    "invalid Poetry package source",
                );
            }
            for (key, kind) in [
                ("python-versions", "requires_python"),
                ("category", "lock_group"),
                ("optional", "optional"),
                ("develop", "editable"),
                ("groups", "groups"),
                ("markers", "marker"),
                ("extras", "extras"),
                ("dependencies", "dependencies"),
            ] {
                if let Some(item) = package.get(key) {
                    if key == "groups" {
                        if let Some(array) = item.as_array() {
                            for value in array {
                                if let Some(group) = value.as_str() {
                                    row.conditions.push(condition("lock_group", group));
                                } else {
                                    row.complete = false;
                                    self.gap(
                                        value.span().unwrap_or(0..0),
                                        Gap::Malformed,
                                        "Poetry lock group must be a string",
                                    );
                                }
                            }
                        } else {
                            row.complete = false;
                            self.gap(
                                item.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "Poetry lock groups must be an array",
                            );
                        }
                        continue;
                    }
                    if key == "optional" {
                        match item.as_bool() {
                            Some(true) => row.conditions.push(condition("optional", "true")),
                            Some(false) => {}
                            None => {
                                row.complete = false;
                                self.gap(
                                    item.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "Poetry optional flag must be boolean",
                                );
                            }
                        }
                        continue;
                    }
                    if key == "develop" {
                        if let Some(editable) = item.as_bool() {
                            row.conditions
                                .push(condition("editable", &editable.to_string()));
                        } else {
                            row.complete = false;
                            self.gap(
                                item.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "Poetry develop flag must be boolean",
                            );
                        }
                        continue;
                    }
                    if key == "python-versions" {
                        if let Some(raw) = item.as_str() {
                            if raw != "*" && VersionSpecifiers::from_str(raw).is_err() {
                                row.complete = false;
                                self.gap(
                                    item.span().unwrap_or(0..0),
                                    Gap::Unsupported,
                                    "unsupported Poetry Python version constraint",
                                );
                            }
                        } else {
                            row.complete = false;
                            self.gap(
                                item.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "python-versions must be a string",
                            );
                        }
                    }
                    // Poetry 2.1 markers may be keyed by group. Preserve the
                    // table rather than flattening alternatives into AND.
                    if key == "markers"
                        && item
                            .as_str()
                            .is_some_and(|raw| pep508_rs::MarkerTree::from_str(raw).is_err())
                    {
                        row.complete = false;
                        self.gap(
                            item.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "invalid Poetry marker",
                        );
                    }
                    if key == "markers" && item.as_table_like().is_some() {
                        self.gap(
                            item.span().unwrap_or(0..0),
                            Gap::Unsupported,
                            "Poetry group-keyed marker selection is preserved but not evaluated",
                        );
                    } else if key == "markers" && item.as_str().is_none() {
                        row.complete = false;
                        self.gap(
                            item.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "Poetry markers must be a string or group-keyed table",
                        );
                    }
                    row.conditions
                        .push(condition(kind, item.as_str().unwrap_or(&item.to_string())));
                }
            }
            self.output.rows.push(row);
        }
    }

    fn exact_lock_version(&mut self, item: Option<&Item>, row: &mut DependencyEvidence) {
        match item
            .and_then(Item::as_str)
            .and_then(|raw| Version::from_str(raw).ok())
        {
            Some(version) => row.exact_version = Some(version.to_string()),
            None => {
                row.complete = false;
                self.gap(
                    row.byte_range.clone(),
                    Gap::Unresolved,
                    "missing or invalid PEP 440 lock version",
                );
            }
        }
    }

    fn lock_markers(&mut self, item: &Item, kind: &str, conditions: &mut Vec<DependencyCondition>) {
        let Some(array) = item.as_array() else {
            conditions.push(condition("unresolved_marker", &item.to_string()));
            self.gap(
                item.span().unwrap_or(0..0),
                Gap::Malformed,
                "lock markers must be an array",
            );
            return;
        };
        for value in array {
            match value
                .as_str()
                .and_then(|raw| pep508_rs::MarkerTree::from_str(raw).ok())
            {
                Some(marker) => {
                    // Keep true alternatives in an OR array. Dropping one
                    // would accidentally narrow an unconditional candidate.
                    let text = marker
                        .contents()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| value.as_str().unwrap().to_owned());
                    conditions.push(condition(kind, &text));
                }
                None => {
                    conditions.push(condition("unresolved_marker", &value.to_string()));
                    self.gap(
                        value.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "invalid lock marker",
                    );
                }
            }
        }
    }
}

/// Sources are structured scalars. Canonical JSON preserves type and all
/// identity keys (including git references), independent of TOML trivia.
fn source_identity(item: &Item, keys: &[&str]) -> Option<String> {
    let table = item.as_table_like()?;
    let mut object = serde_json::Map::new();
    for (key, item) in table.iter() {
        if !keys.contains(&key) {
            return None;
        }
        let value = serde_json::Value::String(item.as_str()?.to_owned());
        object.insert(key.to_owned(), value);
    }
    (!object.is_empty()).then(|| serde_json::Value::Object(object).to_string())
}

fn uv_source_identity(item: &Item) -> Option<String> {
    const KEYS: &[&str] = &["registry", "git", "url", "editable", "virtual", "directory"];
    (item.as_table_like()?.len() == 1).then_some(())?;
    source_identity(item, KEYS)
}

impl Reader<'_> {
    pub(super) fn uv_sources(&mut self, uv: &Item) {
        let Some(sources) = uv.get("sources") else {
            return;
        };
        let Some(table) = sources.as_table_like() else {
            self.gap(
                sources.span().unwrap_or(0..0),
                Gap::Malformed,
                "uv sources must be a table",
            );
            return;
        };
        for (name, item) in table.iter() {
            let Ok(name) = PackageName::from_str(name) else {
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid uv source distribution name",
                );
                continue;
            };
            let alternatives = match item.as_array() {
                Some(array) => array
                    .iter()
                    .map(|value| Item::Value(value.clone()))
                    .collect::<Vec<_>>(),
                None => vec![item.clone()],
            };
            let declarations = self
                .output
                .rows
                .iter()
                .filter(|row| {
                    row.kind == Kind::Declared
                        && row.package == name.as_ref()
                        && !row.conditions.contains(&condition("role", "project"))
                })
                .cloned()
                .collect::<Vec<_>>();
            if declarations.is_empty() {
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Unresolved,
                    "uv source has no declared requirement",
                );
                continue;
            }
            for alternative in alternatives {
                let Some(table) = alternative.as_table_like() else {
                    self.gap(
                        alternative.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "uv source must be a table",
                    );
                    continue;
                };
                let mut source = serde_json::Map::new();
                let mut conditions = Vec::new();
                let mut complete = true;
                for (key, value) in table.iter() {
                    match key {
                        "marker" => match value
                            .as_str()
                            .and_then(|raw| pep508_rs::MarkerTree::from_str(raw).ok())
                        {
                            Some(marker) => {
                                if let Some(contents) = marker.contents() {
                                    conditions.push(condition("marker", &contents.to_string()));
                                }
                            }
                            None => {
                                complete = false;
                                self.gap(
                                    value.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "invalid uv source marker",
                                );
                            }
                        },
                        "extra" | "group" => {
                            if let Some(value) = value.as_str() {
                                conditions.push(condition(&format!("source_{key}"), value));
                            } else {
                                complete = false;
                                self.gap(
                                    value.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "invalid uv source condition",
                                );
                            }
                        }
                        "path" | "git" | "url" | "index" | "rev" | "tag" | "branch"
                        | "subdirectory" => {
                            if let Some(value) = value.as_str() {
                                source.insert(
                                    key.to_owned(),
                                    serde_json::Value::String(value.to_owned()),
                                );
                            } else {
                                complete = false;
                                self.gap(
                                    value.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "invalid uv source identity",
                                );
                            }
                        }
                        "editable" | "workspace" => {
                            if let Some(value) = value.as_bool() {
                                source.insert(key.to_owned(), serde_json::Value::Bool(value));
                            } else {
                                complete = false;
                                self.gap(
                                    value.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "invalid uv source flag",
                                );
                            }
                        }
                        _ => {
                            complete = false;
                            self.gap(
                                value.span().unwrap_or(0..0),
                                Gap::Unsupported,
                                &format!("unsupported uv source key {key}"),
                            );
                        }
                    }
                }
                if source.is_empty() {
                    complete = false;
                    self.gap(
                        alternative.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "uv source has no source identity",
                    );
                }
                for declaration in &declarations {
                    if self.stopped() {
                        break;
                    }
                    let mut row = declaration.clone();
                    row.source = Some(serde_json::Value::Object(source.clone()).to_string());
                    row.byte_range = alternative.span().unwrap_or(0..0);
                    row.complete &= complete;
                    row.conditions.extend(conditions.iter().cloned());
                    row.conditions.push(condition("source_override", "uv"));
                    row.conditions.push(condition(
                        "declaration_range",
                        &format!(
                            "{}:{}",
                            declaration.byte_range.start, declaration.byte_range.end
                        ),
                    ));
                    self.output.rows.push(row);
                }
            }
        }
    }
}
