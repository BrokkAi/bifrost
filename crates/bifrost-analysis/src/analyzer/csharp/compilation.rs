//! Bounded C# source-to-compilation membership for compilation-wide facts.
//!
//! A `global using` applies to the compilation that contains its source file,
//! not to every C# file below the analyzer workspace root. This index derives
//! the common, statically decidable MSBuild item shapes without executing
//! MSBuild. Unsupported or ambiguous shapes retain their proven memberships
//! but make the index incomplete, so callers can preserve partial evidence
//! without presenting it as authoritative.

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnitIndex, Project, ProjectFile};
use crate::hash::{HashMap, HashSet};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use super::CSharpAnalyzer;

const CONFIG_IDENTITY_DOMAIN: &[u8] = b"bifrost-csharp-compilation-config:v1";
const MAX_PROJECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROJECT_FILES: usize = 4 * 1024;
const MAX_CONFIG_FILES: usize = 16 * 1024;
const MAX_XML_DEPTH: usize = 128;
const MAX_XML_NODES: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct CSharpCompilationIndex {
    memberships: HashMap<ProjectFile, Vec<usize>>,
    complete: bool,
    unresolved_scopes: Vec<ProjectFile>,
    config_digest: Option<StableDigest>,
}

impl CSharpCompilationIndex {
    pub(super) fn build(project: &dyn Project, analyzed_files: &[ProjectFile]) -> Self {
        let mut analyzed = analyzed_files.to_vec();
        analyzed.sort();
        analyzed.dedup();
        let analyzed_set = analyzed.iter().cloned().collect::<HashSet<_>>();

        let Ok(workspace_files) = project.all_files_shared() else {
            return Self {
                memberships: HashMap::default(),
                complete: false,
                unresolved_scopes: analyzed,
                config_digest: None,
            };
        };
        let mut project_files = workspace_files
            .iter()
            .filter(|file| has_extension(file.rel_path(), "csproj"))
            .take(MAX_PROJECT_FILES.saturating_add(1))
            .cloned()
            .collect::<Vec<_>>();
        let project_limit_exceeded = project_files.len() > MAX_PROJECT_FILES;
        let project_overflow = project_files.get(MAX_PROJECT_FILES).cloned();
        project_files.truncate(MAX_PROJECT_FILES);
        let mut config_files = workspace_files
            .iter()
            .filter(|file| {
                has_extension(file.rel_path(), "csproj")
                    || has_extension(file.rel_path(), "props")
                    || has_extension(file.rel_path(), "targets")
            })
            .take(MAX_CONFIG_FILES.saturating_add(1))
            .cloned()
            .collect::<Vec<_>>();
        let config_limit_exceeded = config_files.len() > MAX_CONFIG_FILES;
        let config_overflow = config_files.get(MAX_CONFIG_FILES).cloned();
        config_files.truncate(MAX_CONFIG_FILES);

        let mut complete = !project_limit_exceeded && !config_limit_exceeded;
        let mut unresolved = HashSet::default();
        unresolved.extend(project_overflow.into_iter().chain(config_overflow));
        if project_files.len() > 1 {
            // Source membership is enough to prevent workspace-wide global
            // using hubs, but ordinary cross-project visibility additionally
            // depends on evaluated ProjectReference edges. Until those are
            // modeled, a multi-project file graph is useful partial evidence,
            // not an authoritative compilation graph.
            complete = false;
            unresolved.extend(project_files.iter().cloned());
        }
        let mut hasher = CanonicalHasher::new(CONFIG_IDENTITY_DOMAIN);
        let mut digest_available = !config_limit_exceeded;
        for file in &config_files {
            let Some(source) = read_bounded_source(project, file) else {
                digest_available = false;
                complete = false;
                unresolved.insert(file.clone());
                continue;
            };
            hasher.value(normalized_rel_path(file).as_bytes());
            hasher.value(source.as_bytes());
            if is_directory_build_input(file.rel_path()) {
                // Directory.Build files can add or remove Compile items from
                // every descendant project. Until their MSBuild import scope
                // is modeled, project-local facts remain partial.
                complete = false;
                unresolved.insert(file.clone());
            }
        }
        let config_digest = digest_available.then(|| StableDigest::from_array(hasher.finish()));

        if project_files.is_empty() {
            let memberships = analyzed.into_iter().map(|file| (file, vec![0])).collect();
            let mut unresolved_scopes = unresolved.into_iter().collect::<Vec<_>>();
            unresolved_scopes.sort();
            return Self {
                memberships,
                complete,
                unresolved_scopes,
                config_digest,
            };
        }

        let mut memberships: HashMap<ProjectFile, Vec<usize>> = HashMap::default();
        for (compilation, project_file) in project_files.iter().enumerate() {
            let Some(source) = read_bounded_source(project, project_file) else {
                complete = false;
                unresolved.insert(project_file.clone());
                continue;
            };
            let parsed = parse_project(&source);
            if !parsed.complete {
                complete = false;
                unresolved.insert(project_file.clone());
            }

            let project_directory = project_file.rel_path().parent().unwrap_or(Path::new(""));
            let mut members = HashSet::default();
            if parsed.default_compile_items {
                members.extend(
                    analyzed
                        .iter()
                        .filter(|file| {
                            file.rel_path().starts_with(project_directory)
                                && !has_build_output_component(
                                    file.rel_path()
                                        .strip_prefix(project_directory)
                                        .expect("prefix was checked"),
                                )
                        })
                        .cloned(),
                );
            }

            for operation in parsed.operations {
                let Some(path) = resolve_item_path(project_directory, &operation.path) else {
                    complete = false;
                    unresolved.insert(project_file.clone());
                    continue;
                };
                if let Some(exclude) = operation.exclude.as_deref() {
                    let Some(excluded_path) = resolve_item_path(project_directory, exclude) else {
                        complete = false;
                        unresolved.insert(project_file.clone());
                        continue;
                    };
                    if excluded_path == path {
                        continue;
                    }
                }
                let Some(file) = project.file_by_rel_path(&path) else {
                    if matches!(operation.kind, CompileOperationKind::Include) {
                        complete = false;
                        unresolved.insert(project_file.clone());
                    }
                    continue;
                };
                match operation.kind {
                    CompileOperationKind::Include => {
                        if analyzed_set.contains(&file) {
                            members.insert(file);
                        }
                    }
                    CompileOperationKind::Remove => {
                        members.remove(&file);
                    }
                }
            }

            for file in members {
                memberships.entry(file).or_default().push(compilation);
            }
        }

        for compilation_ids in memberships.values_mut() {
            compilation_ids.sort_unstable();
            compilation_ids.dedup();
            if compilation_ids.len() > 1 {
                // The current coarse graph has one physical node per source,
                // so it cannot keep the global-using environments of two
                // compiled instances separate.
                complete = false;
            }
        }
        for file in analyzed {
            match memberships.get(&file) {
                None => {
                    complete = false;
                    unresolved.insert(file);
                }
                Some(compilations) if compilations.len() > 1 => {
                    unresolved.insert(file);
                }
                Some(_) => {}
            }
        }

        let mut unresolved_scopes = unresolved.into_iter().collect::<Vec<_>>();
        unresolved_scopes.sort();
        Self {
            memberships,
            complete,
            unresolved_scopes,
            config_digest,
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(super) fn unresolved_scopes(&self) -> &[ProjectFile] {
        &self.unresolved_scopes
    }

    pub(super) fn config_digest(&self) -> Option<StableDigest> {
        self.config_digest
    }

    /// Return only compilation-proven edges. A source with unresolved
    /// membership never receives a workspace-wide fallback edge.
    pub(super) fn global_using_dependencies(
        &self,
        analyzed_files: &[ProjectFile],
        global_using_files: &[ProjectFile],
    ) -> HashMap<ProjectFile, HashSet<ProjectFile>> {
        let globals = global_using_files
            .iter()
            .filter_map(|file| self.memberships.get(file).map(|ids| (file, ids)))
            .collect::<Vec<_>>();
        let mut by_file = HashMap::default();
        for file in analyzed_files {
            let Some(compilations) = self.memberships.get(file) else {
                continue;
            };
            let dependencies = globals
                .iter()
                .filter(|(_, global_compilations)| {
                    sorted_intersects(compilations, global_compilations)
                })
                .map(|(global, _)| (*global).clone())
                .collect::<HashSet<_>>();
            if !dependencies.is_empty() {
                by_file.insert(file.clone(), dependencies);
            }
        }
        by_file
    }
}

impl CSharpAnalyzer {
    pub(super) fn compilation_index(&self) -> Arc<CSharpCompilationIndex> {
        self.memo_caches
            .compilation_index
            .get_or_build_on_dedicated_pool(|| {
                CSharpCompilationIndex::build(self.inner.project(), &self.inner.analyzed_files())
            })
    }
}

#[derive(Debug)]
struct ParsedProject {
    default_compile_items: bool,
    operations: Vec<CompileOperation>,
    complete: bool,
}

#[derive(Debug)]
struct CompileOperation {
    kind: CompileOperationKind,
    path: String,
    /// An `Exclude` filters only this `Include` item; it is not a removal
    /// from the compilation's pre-existing SDK default items.
    exclude: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum CompileOperationKind {
    Include,
    Remove,
}

#[derive(Debug)]
struct ElementFrame {
    name: String,
    conditioned: bool,
}

#[derive(Debug)]
struct PropertyCapture {
    depth: usize,
    conditioned: bool,
    kind: PropertyKind,
    text: String,
}

#[derive(Debug, Clone, Copy)]
enum PropertyKind {
    EnableDefaultItems,
    EnableDefaultCompileItems,
    UnsupportedDefaultExcludes,
}

fn parse_project(source: &str) -> ParsedProject {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<ElementFrame>::new();
    let mut operations = Vec::new();
    let mut sdk_project = false;
    let mut default_items_override = None;
    let mut default_compile_items_override = None;
    let mut complete = true;
    let mut capture = None::<PropertyCapture>;
    let mut buffer = Vec::new();
    let mut nodes = 0usize;

    loop {
        let event = match reader.read_event_into(&mut buffer) {
            Ok(event) => event,
            Err(_) => {
                complete = false;
                break;
            }
        };
        match event {
            Event::Start(start) => {
                nodes = nodes.saturating_add(1);
                if nodes > MAX_XML_NODES || stack.len() >= MAX_XML_DEPTH {
                    complete = false;
                    break;
                }
                let Some(name) = local_xml_name(start.name().as_ref()) else {
                    complete = false;
                    break;
                };
                let parent_conditioned = stack.last().is_some_and(|frame| frame.conditioned);
                let attributes = match element_attributes(&reader, &start) {
                    Some(attributes) => attributes,
                    None => {
                        complete = false;
                        break;
                    }
                };
                let conditioned =
                    parent_conditioned || attributes.iter().any(|(name, _)| name == "Condition");
                if name == "Project" {
                    if conditioned {
                        complete = false;
                    }
                    if let Some(sdk) = attribute(&attributes, "Sdk") {
                        if conditioned || !static_property_value(sdk) {
                            complete = false;
                        } else {
                            sdk_project = !sdk.trim().is_empty();
                        }
                    }
                }
                if name == "Sdk" {
                    if conditioned
                        || attributes
                            .iter()
                            .any(|(_, value)| !static_property_value(value))
                    {
                        complete = false;
                    } else {
                        sdk_project = true;
                    }
                }
                if name == "Import" {
                    complete = false;
                }
                if name == "Compile" {
                    collect_compile_operation(
                        &attributes,
                        conditioned,
                        &mut operations,
                        &mut complete,
                    );
                }
                stack.push(ElementFrame {
                    name: name.clone(),
                    conditioned,
                });
                if let Some(kind) = property_kind(&name) {
                    capture = Some(PropertyCapture {
                        depth: stack.len(),
                        conditioned,
                        kind,
                        text: String::new(),
                    });
                }
            }
            Event::Empty(empty) => {
                nodes = nodes.saturating_add(1);
                if nodes > MAX_XML_NODES {
                    complete = false;
                    break;
                }
                let Some(name) = local_xml_name(empty.name().as_ref()) else {
                    complete = false;
                    break;
                };
                let attributes = match element_attributes(&reader, &empty) {
                    Some(attributes) => attributes,
                    None => {
                        complete = false;
                        break;
                    }
                };
                let conditioned = stack.last().is_some_and(|frame| frame.conditioned)
                    || attributes.iter().any(|(name, _)| name == "Condition");
                if name == "Project" {
                    if conditioned {
                        complete = false;
                    }
                    if let Some(sdk) = attribute(&attributes, "Sdk") {
                        if conditioned || !static_property_value(sdk) {
                            complete = false;
                        } else {
                            sdk_project = !sdk.trim().is_empty();
                        }
                    }
                } else if name == "Sdk" {
                    if conditioned
                        || attributes
                            .iter()
                            .any(|(_, value)| !static_property_value(value))
                    {
                        complete = false;
                    } else {
                        sdk_project = true;
                    }
                } else if name == "Import" {
                    complete = false;
                } else if name == "Compile" {
                    collect_compile_operation(
                        &attributes,
                        conditioned,
                        &mut operations,
                        &mut complete,
                    );
                }
            }
            Event::Text(text) => {
                if let Some(capture) = capture.as_mut() {
                    match text.xml10_content() {
                        Ok(text) => capture.text.push_str(&text),
                        Err(_) => complete = false,
                    }
                }
            }
            Event::CData(text) => {
                if let Some(capture) = capture.as_mut() {
                    match text.decode() {
                        Ok(text) => capture.text.push_str(&text),
                        Err(_) => complete = false,
                    }
                }
            }
            Event::End(end) => {
                if capture
                    .as_ref()
                    .is_some_and(|capture| capture.depth == stack.len())
                {
                    let property = capture.take().expect("capture was checked");
                    if property.conditioned {
                        complete = false;
                    } else {
                        match property.kind {
                            PropertyKind::EnableDefaultItems => {
                                parse_bool_property(
                                    &property.text,
                                    &mut default_items_override,
                                    &mut complete,
                                );
                            }
                            PropertyKind::EnableDefaultCompileItems => {
                                parse_bool_property(
                                    &property.text,
                                    &mut default_compile_items_override,
                                    &mut complete,
                                );
                            }
                            PropertyKind::UnsupportedDefaultExcludes => complete = false,
                        }
                    }
                }
                let end_name = local_xml_name(end.name().as_ref());
                if stack
                    .pop()
                    .is_none_or(|frame| end_name.as_deref() != Some(frame.name.as_str()))
                {
                    complete = false;
                    break;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !stack.is_empty() || capture.is_some() {
        complete = false;
    }
    ParsedProject {
        default_compile_items: sdk_project
            && default_items_override.unwrap_or(true)
            && default_compile_items_override.unwrap_or(true),
        operations,
        complete,
    }
}

fn property_kind(name: &str) -> Option<PropertyKind> {
    match name {
        "EnableDefaultItems" => Some(PropertyKind::EnableDefaultItems),
        "EnableDefaultCompileItems" => Some(PropertyKind::EnableDefaultCompileItems),
        "DefaultItemExcludes" | "DefaultExcludesInProjectFolder" => {
            Some(PropertyKind::UnsupportedDefaultExcludes)
        }
        _ => None,
    }
}

fn parse_bool_property(value: &str, target: &mut Option<bool>, complete: &mut bool) {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => *target = Some(true),
        "false" => *target = Some(false),
        _ => *complete = false,
    }
}

fn static_property_value(value: &str) -> bool {
    !value.bytes().any(|byte| matches!(byte, b'$' | b'@' | b'%'))
}

fn collect_compile_operation(
    attributes: &[(String, String)],
    conditioned: bool,
    operations: &mut Vec<CompileOperation>,
    complete: &mut bool,
) {
    if conditioned {
        *complete = false;
        return;
    }
    let include = attribute(attributes, "Include");
    let remove = attribute(attributes, "Remove");
    let exclude = attribute(attributes, "Exclude");
    if include.is_some() && remove.is_some() {
        *complete = false;
        return;
    }
    if let Some(path) = include {
        if !static_item_path(path) {
            *complete = false;
            return;
        }
        if exclude.is_some_and(|excluded| !static_item_path(excluded)) {
            *complete = false;
            return;
        }
        operations.push(CompileOperation {
            kind: CompileOperationKind::Include,
            path: path.to_owned(),
            exclude: exclude.map(str::to_owned),
        });
    } else if let Some(path) = remove {
        if static_item_path(path) {
            operations.push(CompileOperation {
                kind: CompileOperationKind::Remove,
                path: path.to_owned(),
                exclude: None,
            });
        } else {
            *complete = false;
        }
    }
}

fn element_attributes(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
) -> Option<Vec<(String, String)>> {
    element
        .attributes()
        .map(|attribute| {
            let attribute = attribute.ok()?;
            let name = local_xml_name(attribute.key.as_ref())?;
            let value = attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .ok()?
                .into_owned();
            Some((name, value))
        })
        .collect()
}

fn attribute<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn local_xml_name(name: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(name).ok()?;
    Some(
        name.rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(name)
            .to_owned(),
    )
}

fn static_item_path(path: &str) -> bool {
    let path = path.trim();
    !path.is_empty()
        && !path
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b';' | b'$' | b'@' | b'%'))
}

fn resolve_item_path(project_directory: &Path, raw: &str) -> Option<PathBuf> {
    let portable = raw
        .trim()
        .chars()
        .map(|character| if character == '\\' { '/' } else { character })
        .collect::<String>();
    let item = Path::new(&portable);
    if item.is_absolute() {
        return None;
    }
    let mut components = Vec::<OsString>::new();
    for component in project_directory.join(item).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::ParentDir => {
                components.pop()?;
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(components.into_iter().collect())
}

fn sorted_intersects(left: &[usize], right: &[usize]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn read_bounded_source(project: &dyn Project, file: &ProjectFile) -> Option<String> {
    project
        .read_source_limited(file, MAX_PROJECT_BYTES)
        .ok()
        .flatten()
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn has_build_output_component(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(component) = component else {
            return false;
        };
        component.eq_ignore_ascii_case("bin") || component.eq_ignore_ascii_case("obj")
    })
}

fn is_directory_build_input(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("Directory.Build.props")
                || name.eq_ignore_ascii_case("Directory.Build.targets")
        })
}

fn normalized_rel_path(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, OverlayProject, TestProject};
    use std::fs;

    fn fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, TestProject, Vec<ProjectFile>) {
        let root = tempfile::tempdir().expect("temporary project");
        for (path, source) in files {
            let path = root.path().join(path);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("create parent");
            fs::write(path, source).expect("write fixture");
        }
        let project = TestProject::new(root.path(), Language::CSharp);
        let analyzed = project
            .analyzable_files(Language::CSharp)
            .expect("C# files")
            .into_iter()
            .collect();
        (root, project, analyzed)
    }

    fn file(project: &TestProject, path: &str) -> ProjectFile {
        project
            .file_by_rel_path(Path::new(path))
            .expect("fixture file")
    }

    #[test]
    fn sibling_projects_scope_global_using_sources() {
        let (_root, project, analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
            ("B/B.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("B/App.cs", "namespace B; class App {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "A/GlobalUsings.cs");
        let dependencies =
            index.global_using_dependencies(&analyzed, std::slice::from_ref(&global));

        assert!(!index.is_complete());
        assert!(
            index
                .unresolved_scopes()
                .contains(&file(&project, "A/A.csproj"))
        );
        assert!(dependencies[&file(&project, "A/App.cs")].contains(&global));
        assert!(!dependencies.contains_key(&file(&project, "B/App.cs")));
    }

    #[test]
    fn explicit_linked_source_joins_the_declaring_compilation() {
        let (_root, project, analyzed) = fixture(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Shared/Linked.cs\"><Link>Linked.cs</Link></Compile></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("Shared/Linked.cs", "namespace Shared; class Linked {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "A/GlobalUsings.cs");
        let dependencies =
            index.global_using_dependencies(&analyzed, std::slice::from_ref(&global));

        assert!(index.is_complete(), "{:?}", index.unresolved_scopes());
        assert!(dependencies[&file(&project, "Shared/Linked.cs")].contains(&global));
    }

    #[test]
    fn source_set_without_csproj_is_one_loose_compilation() {
        let (_root, project, analyzed) = fixture(&[
            ("GlobalUsings.cs", "global using Demo;"),
            ("App.cs", "namespace Demo; class App {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "GlobalUsings.cs");
        let dependencies =
            index.global_using_dependencies(&analyzed, std::slice::from_ref(&global));

        assert!(index.is_complete());
        assert!(dependencies[&file(&project, "App.cs")].contains(&global));
    }

    #[test]
    fn unresolved_msbuild_item_is_incomplete_without_workspace_fallback() {
        let (_root, project, analyzed) = fixture(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"$(SharedRoot)/Linked.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
            ("Loose/Other.cs", "namespace Loose; class Other {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "A/GlobalUsings.cs");
        let dependencies =
            index.global_using_dependencies(&analyzed, std::slice::from_ref(&global));

        assert!(!index.is_complete());
        assert!(
            index
                .unresolved_scopes()
                .contains(&file(&project, "A/A.csproj"))
        );
        assert!(!dependencies.contains_key(&file(&project, "Loose/Other.cs")));
    }

    #[test]
    fn one_physical_source_in_two_compilations_is_reported_ambiguous() {
        let (_root, project, analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            (
                "A/Nested/Nested.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
            ),
            ("A/Nested/Shared.cs", "namespace Shared; class Value {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);

        assert!(!index.is_complete());
        assert!(
            index
                .unresolved_scopes()
                .contains(&file(&project, "A/Nested/Shared.cs"))
        );
    }

    #[test]
    fn config_only_edit_rotates_the_compilation_digest() {
        let (root, project, analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let before = CSharpCompilationIndex::build(&project, &analyzed)
            .config_digest()
            .expect("initial config digest");

        fs::write(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Nullable>enable</Nullable></PropertyGroup></Project>",
        )
        .expect("edit project file");
        let after = CSharpCompilationIndex::build(&project, &analyzed)
            .config_digest()
            .expect("updated config digest");

        assert_ne!(before, after);
    }

    #[test]
    fn disabled_default_items_do_not_claim_directory_sources() {
        let (_root, project, analyzed) = fixture(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultItems>false</EnableDefaultItems></PropertyGroup><ItemGroup><Compile Include=\"GlobalUsings.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/Unlisted.cs", "namespace A; class Unlisted {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "A/GlobalUsings.cs");
        let dependencies = index.global_using_dependencies(&analyzed, &[global]);

        assert!(!index.is_complete());
        assert!(
            index
                .unresolved_scopes()
                .contains(&file(&project, "A/Unlisted.cs"))
        );
        assert!(!dependencies.contains_key(&file(&project, "A/Unlisted.cs")));
    }

    #[test]
    fn custom_default_excludes_are_reported_incomplete() {
        let (_root, project, analyzed) = fixture(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><DefaultItemExcludes>Generated/**/*.cs</DefaultItemExcludes></PropertyGroup></Project>",
            ),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);

        assert!(!index.is_complete());
        assert!(
            index
                .unresolved_scopes()
                .contains(&file(&project, "A/A.csproj"))
        );
    }

    #[test]
    fn literal_exclude_filters_only_its_include_item() {
        let (_root, project, analyzed) = fixture(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include=\"GlobalUsings.cs\" /><Compile Include=\"App.cs\" Exclude=\"GlobalUsings.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let index = CSharpCompilationIndex::build(&project, &analyzed);
        let global = file(&project, "A/GlobalUsings.cs");
        let dependencies =
            index.global_using_dependencies(&analyzed, std::slice::from_ref(&global));

        assert!(index.is_complete(), "{:?}", index.unresolved_scopes());
        assert!(dependencies[&file(&project, "A/App.cs")].contains(&global));
    }

    #[test]
    fn conditional_sdk_declarations_are_incomplete_without_default_membership() {
        for source in [
            "<Project Sdk=\"Microsoft.NET.Sdk\" Condition=\"'$(UseSdk)' == 'true'\" />",
            "<Project><Sdk Name=\"Microsoft.NET.Sdk\" Condition=\"'$(UseSdk)' == 'true'\" /></Project>",
        ] {
            let parsed = parse_project(source);
            assert!(!parsed.complete, "{source}");
            assert!(!parsed.default_compile_items, "{source}");
        }
    }

    #[test]
    fn project_clone_rebuilds_compilation_config_identity_from_overlay() {
        let (root, project, _analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer = CSharpAnalyzer::new(Arc::clone(&project));
        let before = analyzer
            .compilation_index()
            .config_digest()
            .expect("disk config identity");

        let overlay = Arc::new(OverlayProject::new(project));
        assert!(overlay.set(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Nullable>enable</Nullable></PropertyGroup></Project>".to_owned(),
        ));
        let cloned = analyzer.clone_with_project(overlay);
        let after = cloned
            .compilation_index()
            .config_digest()
            .expect("overlay config identity");

        assert_ne!(before, after);
    }
}
