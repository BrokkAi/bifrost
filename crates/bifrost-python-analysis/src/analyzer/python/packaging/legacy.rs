//! Literal setuptools and bounded Poetry declaration tables.

use crate::analyzer::python::packaging::*;
use brokk_bifrost_python::declarations::{
    SetuptoolsLiteralValue, setuptools_setup_py_literal_arguments,
};

impl Reader<'_> {
    fn setuptools_extra_condition(
        &mut self,
        raw: &str,
        range: Range<usize>,
    ) -> DependencyCondition {
        match pep508_rs::ExtraName::from_str(raw) {
            Ok(extra) => condition("extra", extra.as_ref()),
            Err(_) => {
                self.gap(
                    range,
                    Gap::Unsupported,
                    &format!("unsupported legacy extra selector retained: {raw}"),
                );
                condition("setuptools_extra", raw)
            }
        }
    }
    pub(in crate::analyzer::python::packaging) fn installed_metadata(&mut self) {
        let name = brokk_bifrost_python::distribution::metadata_header(self.source, "Name")
            .and_then(|name| PackageName::from_str(&name).ok());
        let version = brokk_bifrost_python::distribution::metadata_header(self.source, "Version")
            .and_then(|version| Version::from_str(&version).ok());
        let (Some(name), Some(version)) = (name, version) else {
            self.gap(
                0..self.source.len(),
                Gap::Malformed,
                "METADATA needs a valid distribution Name and PEP 440 Version",
            );
            return;
        };
        let mut row = self.row(
            name.to_string(),
            Kind::Installed,
            0..self.source.len(),
            DependencyScope::Unknown,
        );
        row.exact_version = Some(version.to_string());
        row.locator = Some(self.path.to_string_lossy().into_owned());
        self.output.rows.push(row);
    }
    pub(in crate::analyzer::python::packaging) fn setup_py(&mut self) {
        let Some(arguments) = setuptools_setup_py_literal_arguments(self.source) else {
            self.gap(
                0..self.source.len(),
                Gap::Malformed,
                "setup.py syntax could not be parsed",
            );
            return;
        };
        if arguments.is_empty() {
            self.gap(
                0..self.source.len(),
                Gap::Unresolved,
                "no supported imported setuptools setup call",
            );
            return;
        }
        if arguments.iter().any(|argument| argument.call_index != 0) {
            self.gap(
                0..self.source.len(),
                Gap::Conflict,
                "multiple setup calls cannot select one project",
            );
            return;
        }
        let literal = |name: &str| {
            arguments
                .iter()
                .find(|argument| argument.name == name)
                .and_then(|argument| match &argument.value {
                    Some(SetuptoolsLiteralValue::String(value)) => {
                        Some((value.as_str(), argument.byte_range.clone()))
                    }
                    _ => None,
                })
        };
        let mut conditions = Vec::new();
        if let Some((raw, range)) = literal("python_requires") {
            match VersionSpecifiers::from_str(raw) {
                Ok(requirement) => {
                    conditions.push(condition("requires_python", &requirement.to_string()))
                }
                Err(error) => self.gap(range, Gap::Malformed, &error.to_string()),
            }
        }
        if let Some((raw, range)) = literal("name") {
            match PackageName::from_str(raw) {
                Ok(name) => {
                    self.owner = Some(python_project_entity(self.path, name.as_ref()).id());
                    let mut row = self.row(
                        name.to_string(),
                        Kind::Declared,
                        range,
                        DependencyScope::Unknown,
                    );
                    row.source = Some(format!(
                        "workspace:{}",
                        self.path.parent().unwrap_or(Path::new("")).display()
                    ));
                    row.conditions = conditions.clone();
                    row.conditions.push(condition("role", "project"));
                    if let Some((raw, range)) = literal("version") {
                        match Version::from_str(raw) {
                            Ok(version) => row.exact_version = Some(version.to_string()),
                            Err(error) => {
                                row.complete = false;
                                self.gap(range, Gap::Malformed, &error.to_string());
                            }
                        }
                    }
                    if !self.stopped() {
                        self.output.rows.push(row);
                    }
                }
                Err(error) => self.gap(range, Gap::Malformed, &error.to_string()),
            }
        } else {
            self.gap(
                0..self.source.len(),
                Gap::Unresolved,
                "setup.py distribution name is not literal",
            );
        }
        for argument in arguments {
            if self.stopped() {
                break;
            }
            let Some(value) = argument.value else {
                self.gap(
                    argument.byte_range,
                    Gap::Unresolved,
                    &format!("nonliteral setuptools {}", argument.name),
                );
                continue;
            };
            match value {
                SetuptoolsLiteralValue::Strings(requirements) => {
                    let scope = match argument.name.as_str() {
                        "setup_requires" => DependencyScope::Provided,
                        "tests_require" => DependencyScope::Test,
                        _ => DependencyScope::Runtime,
                    };
                    for raw in requirements {
                        self.requirement(
                            &raw,
                            argument.byte_range.clone(),
                            Kind::Declared,
                            scope,
                            &conditions,
                        );
                    }
                }
                SetuptoolsLiteralValue::Extras(extras) => {
                    for (extra, requirements) in extras {
                        let mut conditions = conditions.clone();
                        conditions.push(
                            self.setuptools_extra_condition(&extra, argument.byte_range.clone()),
                        );
                        for raw in requirements {
                            self.requirement(
                                &raw,
                                argument.byte_range.clone(),
                                Kind::Declared,
                                DependencyScope::Optional,
                                &conditions,
                            );
                        }
                    }
                }
                SetuptoolsLiteralValue::String(_) => {}
            }
        }
    }

    pub(in crate::analyzer::python::packaging) fn setup_cfg(&mut self) {
        let mut parser = configparser::ini::Ini::new_cs();
        parser.set_multiline(true);
        parser.set_inline_comment_symbols(None);
        let document = match parser.read(self.source.to_owned()) {
            Ok(document) => document,
            Err(error) => {
                self.gap(0..self.source.len(), Gap::Malformed, &error);
                return;
            }
        };
        let range = 0..self.source.len();
        let name = document
            .get("metadata")
            .and_then(|metadata| metadata.get("name"))
            .and_then(|name| name.as_deref());
        if let Some(name) = name.and_then(|name| PackageName::from_str(name).ok()) {
            self.owner = Some(python_project_entity(self.path, name.as_ref()).id());
            let mut row = self.row(
                name.to_string(),
                Kind::Declared,
                range.clone(),
                DependencyScope::Unknown,
            );
            row.conditions.push(condition("role", "project"));
            if let Some(version) = document
                .get("metadata")
                .and_then(|metadata| metadata.get("version"))
                .and_then(|version| version.as_deref())
            {
                match Version::from_str(version) {
                    Ok(version) => row.exact_version = Some(version.to_string()),
                    Err(_) => {
                        row.complete = false;
                        self.gap(
                            range.clone(),
                            Gap::Unresolved,
                            "nonliteral/invalid setup.cfg version",
                        );
                    }
                }
            }
            self.output.rows.push(row);
        } else {
            self.gap(
                range.clone(),
                Gap::Unresolved,
                "setup.cfg distribution name is missing or invalid",
            );
        }
        let mut conditions = Vec::new();
        if let Some(options) = document.get("options") {
            if let Some(requires) = options
                .get("python_requires")
                .and_then(|value| value.as_deref())
            {
                match VersionSpecifiers::from_str(requires) {
                    Ok(requires) => {
                        conditions.push(condition("requires_python", &requires.to_string()))
                    }
                    Err(_) => self.gap(
                        range.clone(),
                        Gap::Malformed,
                        "invalid setup.cfg python_requires",
                    ),
                }
            }
            for (key, scope) in [
                ("install_requires", DependencyScope::Runtime),
                ("setup_requires", DependencyScope::Provided),
                ("tests_require", DependencyScope::Test),
            ] {
                if let Some(requirements) = options.get(key).and_then(|value| value.as_deref()) {
                    for raw in requirements
                        .lines()
                        .map(str::trim)
                        .filter(|raw| !raw.is_empty())
                    {
                        self.requirement(raw, range.clone(), Kind::Declared, scope, &conditions);
                    }
                }
            }
        }
        if let Some(extras) = document.get("options.extras_require") {
            let mut extras = extras.iter().collect::<Vec<_>>();
            extras.sort_unstable_by_key(|(name, _)| *name);
            for (extra, requirements) in extras {
                let mut conditions = conditions.clone();
                conditions.push(self.setuptools_extra_condition(extra, range.clone()));
                if let Some(requirements) = requirements {
                    for raw in requirements
                        .lines()
                        .map(str::trim)
                        .filter(|raw| !raw.is_empty())
                    {
                        self.requirement(
                            raw,
                            range.clone(),
                            Kind::Declared,
                            DependencyScope::Optional,
                            &conditions,
                        );
                    }
                } else {
                    self.gap(
                        range.clone(),
                        Gap::Malformed,
                        "setup.cfg extra has no value",
                    );
                }
            }
        }
    }

    pub(in crate::analyzer::python::packaging) fn poetry_declarations(&mut self, poetry: &Item) {
        if self.owner.is_none() {
            if let Some(name) = poetry
                .get("name")
                .and_then(Item::as_str)
                .and_then(|name| PackageName::from_str(name).ok())
            {
                self.owner = Some(python_project_entity(self.path, name.as_ref()).id());
                let mut row = self.row(
                    name.to_string(),
                    Kind::Declared,
                    poetry.span().unwrap_or(0..0),
                    DependencyScope::Unknown,
                );
                row.conditions.push(condition("role", "project"));
                if let Some(version) = poetry.get("version") {
                    self.exact_poetry_project_version(version, &mut row);
                }
                self.output.rows.push(row);
            } else {
                self.gap(
                    poetry.span().unwrap_or(0..0),
                    Gap::Unresolved,
                    "Poetry project identity is missing",
                );
            }
        }
        if let Some(dependencies) = poetry.get("dependencies") {
            self.poetry_dependencies(dependencies, DependencyScope::Runtime, &[]);
        }
        if let Some(dependencies) = poetry.get("dev-dependencies") {
            self.poetry_dependencies(
                dependencies,
                DependencyScope::FeatureGated,
                &[condition("group", "dev")],
            );
        }
        if let Some(groups) = poetry.get("group") {
            if let Some(groups) = groups.as_table_like() {
                for (name, group) in groups.iter() {
                    if let Some(dependencies) = group.get("dependencies") {
                        self.poetry_dependencies(
                            dependencies,
                            DependencyScope::FeatureGated,
                            &[condition("group", name)],
                        );
                    }
                }
            } else {
                self.gap(
                    groups.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "Poetry groups must be tables",
                );
            }
        }
        if let Some(extras) = poetry.get("extras") {
            if let Some(table) = extras.as_table_like() {
                for (extra, packages) in table.iter() {
                    let Some(array) = packages.as_array() else {
                        self.gap(
                            packages.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "Poetry extras must be arrays",
                        );
                        continue;
                    };
                    for value in array {
                        let Some(name) = value
                            .as_str()
                            .and_then(|name| PackageName::from_str(name).ok())
                        else {
                            self.gap(
                                value.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "invalid Poetry extra reference",
                            );
                            continue;
                        };
                        for row in &mut self.output.rows {
                            if row.package == name.as_ref()
                                && row.scope == DependencyScope::Optional
                            {
                                row.conditions.push(condition("extra", extra));
                            }
                        }
                    }
                }
            } else {
                self.gap(
                    extras.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "Poetry extras must be a table",
                );
            }
        }
        if let Some(sources) = poetry.get("source") {
            // Priority and fallback can depend on unavailable index contents.
            // Preserve the structured declaration without guessing a default
            // registry or binding a stale lock to configured-index selection.
            self.gap(
                sources.span().unwrap_or(0..0),
                Gap::Unresolved,
                "Poetry configured-index selection remains unresolved",
            );
            for row in &mut self.output.rows {
                if row.conditions.contains(&condition("role", "project")) {
                    row.conditions
                        .push(condition("poetry_sources", &sources.to_string()));
                } else if row.source.is_none()
                    || row.source.as_deref().is_some_and(|source| {
                        serde_json::from_str::<serde_json::Value>(source)
                            .ok()
                            .is_some_and(|source| source.get("source").is_some())
                    })
                {
                    row.conditions
                        .push(condition("source_selection", "poetry-configured-indices"));
                }
            }
        }
    }

    fn exact_poetry_project_version(&mut self, item: &Item, row: &mut DependencyEvidence) {
        match item.as_str().and_then(|raw| Version::from_str(raw).ok()) {
            Some(version) => row.exact_version = Some(version.to_string()),
            None => {
                row.complete = false;
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Unresolved,
                    "Poetry project version is not a literal PEP 440 version",
                );
            }
        }
    }

    fn poetry_dependencies(
        &mut self,
        item: &Item,
        scope: DependencyScope,
        conditions: &[DependencyCondition],
    ) {
        let Some(table) = item.as_table_like() else {
            self.gap(
                item.span().unwrap_or(0..0),
                Gap::Malformed,
                "Poetry dependencies must be a table",
            );
            return;
        };
        for (name, item) in table.iter() {
            if let Some(array) = item.as_array() {
                for value in array {
                    self.poetry_dependency(name, &Item::Value(value.clone()), scope, conditions);
                }
            } else {
                self.poetry_dependency(name, item, scope, conditions);
            }
        }
    }

    fn poetry_dependency(
        &mut self,
        name: &str,
        item: &Item,
        scope: DependencyScope,
        conditions: &[DependencyCondition],
    ) {
        if self.stopped() {
            return;
        }
        if name == "python" {
            let raw = item
                .as_str()
                .or_else(|| item.get("version").and_then(Item::as_str));
            if let Some(raw) = raw {
                let supported = poetry_version_requirement(raw);
                if supported.is_none() {
                    self.gap(
                        item.span().unwrap_or(0..0),
                        Gap::Unsupported,
                        "unsupported Poetry interpreter requirement",
                    );
                }
                for row in &mut self.output.rows {
                    row.conditions.push(condition(
                        "requires_python",
                        supported.as_deref().unwrap_or(raw),
                    ));
                }
            } else {
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid Poetry interpreter requirement",
                );
            }
            return;
        }
        let Ok(name) = PackageName::from_str(name) else {
            self.gap(
                item.span().unwrap_or(0..0),
                Gap::Malformed,
                "invalid Poetry distribution name",
            );
            return;
        };
        let mut row = self.row(
            name.to_string(),
            Kind::Declared,
            item.span().unwrap_or(0..0),
            scope,
        );
        row.locator = Some(item.to_string());
        row.conditions.extend_from_slice(conditions);
        let raw_version = item
            .as_str()
            .or_else(|| item.get("version").and_then(Item::as_str));
        if let Some(raw) = raw_version {
            row.version_requirement = poetry_version_requirement(raw);
            if row.version_requirement.is_none() && raw != "*" {
                row.complete = false;
                row.version_requirement = Some(raw.to_owned());
                self.gap(
                    row.byte_range.clone(),
                    Gap::Unsupported,
                    "unsupported Poetry version syntax retained",
                );
            }
        }
        if let Some(table) = item.as_table_like() {
            let mut source = serde_json::Map::new();
            for (key, value) in table.iter() {
                match key {
                    "git" | "url" | "path" | "source" | "branch" | "tag" | "rev" | "develop" => {
                        if let Some(value) = value.as_str() {
                            source.insert(
                                key.to_owned(),
                                serde_json::Value::String(value.to_owned()),
                            );
                        } else if let Some(value) = value.as_bool() {
                            source.insert(key.to_owned(), serde_json::Value::Bool(value));
                        } else {
                            row.complete = false;
                            self.gap(
                                value.span().unwrap_or(0..0),
                                Gap::Malformed,
                                "invalid Poetry source",
                            );
                        }
                    }
                    "optional" => {
                        if value.as_bool() == Some(true) {
                            row.scope = DependencyScope::Optional;
                        }
                    }
                    "markers" => {
                        match value
                            .as_str()
                            .and_then(|raw| pep508_rs::MarkerTree::from_str(raw).ok())
                        {
                            Some(marker) => {
                                if let Some(contents) = marker.contents() {
                                    row.conditions
                                        .push(condition("marker", &contents.to_string()));
                                }
                            }
                            None => {
                                row.complete = false;
                                self.gap(
                                    value.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    "invalid Poetry marker",
                                );
                            }
                        }
                    }
                    "python" | "platform" | "extras" | "allow-prereleases" => row
                        .conditions
                        .push(condition(key, value.as_str().unwrap_or(&value.to_string()))),
                    "version" => {}
                    _ => {
                        row.complete = false;
                        self.gap(
                            value.span().unwrap_or(0..0),
                            Gap::Unsupported,
                            &format!("unsupported Poetry declaration key {key}"),
                        );
                    }
                }
            }
            if !source.is_empty() {
                row.source = Some(serde_json::Value::Object(source).to_string());
            }
        } else if raw_version.is_none() {
            row.complete = false;
            self.gap(
                row.byte_range.clone(),
                Gap::Malformed,
                "Poetry dependency must be a string or table",
            );
        }
        self.output.rows.push(row);
    }
}

/// Bounded Poetry sugar is translated using the PEP 440 version parser.
/// Disjunctions and unsupported syntax remain raw requirements with a gap.
fn poetry_version_requirement(raw: &str) -> Option<String> {
    if raw == "*" {
        return Some(String::new());
    }
    if let Ok(specifiers) = VersionSpecifiers::from_str(raw) {
        return Some(specifiers.to_string());
    }
    if let Ok(version) = Version::from_str(raw) {
        return Some(format!("=={version}"));
    }
    let (operator, version) = if let Some(version) = raw.strip_prefix('^') {
        ('^', version)
    } else {
        ('~', raw.strip_prefix('~')?)
    };
    let version = Version::from_str(version).ok()?;
    let release = version.release();
    let boundary = if operator == '^' {
        release
            .iter()
            .position(|component| *component != 0)
            .unwrap_or(release.len() - 1)
    } else if release.len() > 1 {
        1
    } else {
        0
    };
    let mut upper = release[..=boundary].to_vec();
    upper[boundary] = upper[boundary].checked_add(1)?;
    let upper = Version::new(upper).with_epoch(version.epoch());
    Some(format!(">={version},<{upper}"))
}
