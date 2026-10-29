//! C# source-to-compilation membership from MSBuild configuration.
//!
//! A `global using` applies to the compilation that contains its source file,
//! and the global namespace a type lookup sees is that of the compilation and
//! the projects it references, not of every C# file below the analyzer
//! workspace root. [`compilation_facts`] derives the common, statically
//! decidable MSBuild shapes from one revision's retained configuration inputs
//! without executing MSBuild; the store publishes them as rows with that
//! revision (`brokk_bifrost_analysis::analyzer::store::csharp_compilation`).
//! Unsupported or ambiguous shapes are recorded gaps that leave membership
//! unproven, never a complete absence.

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_analysis::analyzer::common::local_xml_name;

use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::analyzer::csharp::CSharpAnalyzer;
use brokk_bifrost_analysis::analyzer::store::csharp_compilation::{
    self, CSharpCompilationFact, CSharpCompilationFacts, CSharpCompilationGap,
    CSharpCompilationMetadata, CSharpCompileItem, CSharpCompileItemKind, CSharpConfigurationInput,
    CSharpGlobalUsing, SelectedCSharpCompilations,
};
use brokk_bifrost_analysis::analyzer::store::workspace_inputs::NativeConfigurationOverlayAuthority;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_csharp::graph_support::CSharpCompilationVisibility;

const CONFIG_IDENTITY_DOMAIN: &[u8] = b"bifrost-csharp-compilation-config:v1";
const MAX_PROJECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROJECT_FILES: usize = 4 * 1024;
const MAX_CONFIG_FILES: usize = 16 * 1024;
const MAX_XML_DEPTH: usize = 128;
const MAX_XML_NODES: usize = 64 * 1024;

/// Identity of one workspace listing's MSBuild configuration inputs, present
/// only when every input below the cap was read.
fn read_config_digest(
    project: &dyn Project,
    workspace_files: &BTreeSet<ProjectFile>,
) -> Option<StableDigest> {
    let files = workspace_files
        .iter()
        .filter(|file| {
            has_extension(file.rel_path(), "csproj")
                || has_extension(file.rel_path(), "props")
                || has_extension(file.rel_path(), "targets")
        })
        .take(MAX_CONFIG_FILES.saturating_add(1))
        .collect::<Vec<_>>();
    if files.len() > MAX_CONFIG_FILES {
        return None;
    }
    let mut hasher = CanonicalHasher::new(CONFIG_IDENTITY_DOMAIN);
    for file in files {
        let source = brokk_bifrost_analysis::analyzer::common::read_bounded_source(
            project,
            file,
            MAX_PROJECT_BYTES,
        )?;
        hasher.value(normalized_rel_path(file).as_bytes());
        hasher.value(source.as_bytes());
    }
    Some(StableDigest::from_array(hasher.finish()))
}

/// Imported-file nesting a project's evaluation chain may follow.
const MAX_IMPORT_DEPTH: usize = 8;

/// Membership rules for one revision's MSBuild configuration inputs, ordered
/// by path. Pure: the store calls it while publishing the revision.
///
/// Each SDK project is evaluated statically over its chain of files: the
/// nearest `Directory.Build.props` and `Directory.Packages.props` above it,
/// the project file, then the nearest `Directory.Build.targets`, each preceded
/// by the static `<Import>`s it opens with. Properties take their last value
/// across the chain and items apply in chain order, relative to the project
/// directory. A file in the chain this parser cannot follow is a gap.
pub(crate) fn compilation_facts(inputs: &[CSharpConfigurationInput]) -> CSharpCompilationFacts {
    let mut facts = CSharpCompilationFacts {
        membership_complete: true,
        ..CSharpCompilationFacts::default()
    };
    let gap = |facts: &mut CSharpCompilationFacts, code: &str, path: &str, evidence: &str| {
        facts.gaps.push(CSharpCompilationGap {
            code: code.to_owned(),
            path: path.to_owned(),
            evidence: evidence.to_owned(),
        });
    };
    // Every configuration input parsed once; `None` when unread or not UTF-8.
    let mut parsed = HashMap::<&str, Option<ParsedProject>>::default();
    let mut projects = Vec::new();
    for input in inputs {
        if input.source.is_none() {
            facts.membership_complete = false;
            gap(
                &mut facts,
                "configuration_byte_cap",
                &input.rel_path,
                "configuration input exceeds the publication byte cap",
            );
        }
        let fragment = input
            .source
            .as_deref()
            .and_then(|source| std::str::from_utf8(source).ok())
            .map(parse_project);
        if input.source.is_some() && fragment.is_none() {
            facts.membership_complete = false;
            gap(
                &mut facts,
                "configuration_not_utf8",
                &input.rel_path,
                "configuration input is not UTF-8",
            );
        }
        parsed.insert(input.rel_path.as_str(), fragment);
        if has_extension(Path::new(&input.rel_path), "csproj") {
            projects.push(input.rel_path.as_str());
        }
    }
    if projects.len() > MAX_PROJECT_FILES {
        facts.membership_complete = false;
        gap(
            &mut facts,
            "project_file_cap",
            projects[MAX_PROJECT_FILES],
            &format!("more than {MAX_PROJECT_FILES} project files"),
        );
        projects.truncate(MAX_PROJECT_FILES);
    }
    if projects.is_empty() {
        facts.compilations.push(CSharpCompilationFact {
            project_path: None,
            items: Vec::new(),
            references: Vec::new(),
            references_complete: true,
            transitive_flow: false,
            metadata: CSharpCompilationMetadata {
                global_usings_complete: true,
                internals_visible_to_complete: true,
                ..Default::default()
            },
        });
        return facts;
    }

    // A traversal project builds other projects and compiles no source, so
    // it is not a compilation and no reference can name one.
    let compiles_nothing = |path: &str| {
        parsed
            .get(path)
            .and_then(Option::as_ref)
            .is_some_and(|project| project.compiles_nothing && project.complete)
    };
    let project_paths = projects
        .iter()
        .copied()
        .filter(|path| !compiles_nothing(path))
        .collect::<HashSet<_>>();
    for project_path in projects {
        if compiles_nothing(project_path) {
            continue;
        }
        let directory = Path::new(project_path)
            .parent()
            .expect("a project file path has a parent");
        let Some(Some(project)) = parsed.get(project_path) else {
            // Unread or undecodable (already a gap): its items and
            // references are unknown.
            facts.compilations.push(CSharpCompilationFact {
                project_path: Some(project_path.to_owned()),
                items: Vec::new(),
                references: Vec::new(),
                references_complete: false,
                transitive_flow: false,
                metadata: CSharpCompilationMetadata::default(),
            });
            continue;
        };

        // The evaluation chain, in order. Microsoft.Common.props imports the
        // props files before Microsoft.NET.Sdk.props adds the default Compile
        // item; Sdk.targets expands the default excludes and fills in empty
        // defaults before Microsoft.Common.targets imports
        // Directory.Build.targets.
        // Only the SDK imports those files implicitly; a project without one
        // reaches them only through its own (dynamic, so unsupported)
        // Microsoft.Common imports.
        let mut chain = Vec::<(&str, &ParsedProject)>::new();
        let mut chain_gaps = Vec::<(&str, String)>::new();
        let implicit_imports = |names: &[&'static str]| {
            names
                .iter()
                .filter(|_| !project.sdks.is_empty())
                .filter_map(|name| nearest_input(&parsed, directory, name))
                .collect::<Vec<_>>()
        };
        for path in implicit_imports(&["Directory.Build.props", "Directory.Packages.props"]) {
            expand_chain(&parsed, path, 0, &mut chain, &mut chain_gaps);
        }
        let body_start = chain.len();
        expand_chain(&parsed, project_path, 0, &mut chain, &mut chain_gaps);
        let targets_start = chain.len();
        for path in implicit_imports(&["Directory.Build.targets"]) {
            expand_chain(&parsed, path, 0, &mut chain, &mut chain_gaps);
        }
        let metadata_chain_complete = chain_gaps.is_empty();
        for (path, evidence) in chain_gaps {
            facts.membership_complete = false;
            gap(&mut facts, "unresolved_import", path, &evidence);
        }

        let mut properties = DefaultItemProperties::default();
        let mut output_roots = None;
        let mut default_position = None;
        let mut transitive_flow = project.sdk_project;
        let mut parsed_references_complete = true;
        let mut references_mutated = false;
        let mut operations = Vec::new();
        let mut raw_references = Vec::new();
        for (index, (path, fragment)) in chain.iter().enumerate() {
            if index == body_start {
                default_position = Some(operations.len());
            }
            if index == targets_start {
                output_roots = Some(properties.fill_sdk_defaults());
            }
            let is_project = *path == project_path;
            if !fragment.complete
                || (!is_project && (fragment.sdk_project || fragment.compiles_nothing))
            {
                facts.membership_complete = false;
                gap(
                    &mut facts,
                    "unsupported_project_items",
                    path,
                    "an Import, a condition, a Target, a dynamic item, an unmodeled SDK or an unsupported default-item property",
                );
            }
            if output_roots.is_some() && fragment.properties.sets_output_roots() {
                facts.membership_complete = false;
                gap(
                    &mut facts,
                    "unsupported_project_items",
                    path,
                    "the default Compile excludes are expanded before this file sets an output root",
                );
            }
            properties.overlay(&fragment.properties);
            transitive_flow &= fragment.transitive_flow;
            if !fragment.references_complete {
                parsed_references_complete = false;
                gap(
                    &mut facts,
                    "unsupported_project_reference",
                    path,
                    "a ProjectReference is conditioned, inside a Target, dynamic or carries unsupported metadata",
                );
            }
            if fragment.references_mutated {
                references_mutated = true;
                gap(
                    &mut facts,
                    "unsupported_project_reference",
                    path,
                    "a ProjectReference Remove, Update or item definition can change any reference",
                );
            }
            operations.extend(fragment.operations.iter().cloned());
            raw_references.extend(fragment.references.iter().map(|raw| (*path, raw)));
        }
        let (base_output, base_intermediate) =
            output_roots.unwrap_or_else(|| properties.fill_sdk_defaults());
        let mut enabled =
            |value: &Option<String>| match value.as_deref().map(str::to_ascii_lowercase) {
                Some(value) if value == "true" => true,
                // An empty value written after the SDK filled in its default is
                // not `true`.
                Some(value) if value.is_empty() || value == "false" => false,
                value => {
                    facts.membership_complete = false;
                    gap(
                        &mut facts,
                        "unsupported_project_items",
                        project_path,
                        &format!("a default-item property has the value {value:?}"),
                    );
                    false
                }
            };
        let default_items = project.sdk_project
            && enabled(&properties.enable_default_items)
            && enabled(&properties.enable_default_compile_items);
        if default_items {
            let mut excluded_trees = Vec::new();
            for root in [base_output, base_intermediate] {
                if static_item_path(&root) {
                    excluded_trees.push(root);
                } else {
                    facts.membership_complete = false;
                    gap(&mut facts, "unresolved_compile_item", project_path, &root);
                }
            }
            // A project its own props import revisits is not in the chain
            // (a recorded gap); its default item position is then moot.
            operations.insert(
                default_position.unwrap_or(operations.len()),
                CompileOperation {
                    kind: CompileOperationKind::DefaultTree,
                    path: ".".to_owned(),
                    exclude: None,
                    excluded_trees,
                },
            );
        }

        // Item paths are relative to the project directory, wherever the
        // item was written.
        let mut items = Vec::new();
        for operation in operations {
            let Some(path) = resolve_item_path(directory, &operation.path) else {
                facts.membership_complete = false;
                gap(
                    &mut facts,
                    "unresolved_compile_item",
                    project_path,
                    &operation.path,
                );
                continue;
            };
            if let Some(exclude) = operation.exclude.as_deref() {
                let Some(excluded) = resolve_item_path(directory, exclude) else {
                    facts.membership_complete = false;
                    gap(&mut facts, "unresolved_compile_item", project_path, exclude);
                    continue;
                };
                if excluded == path {
                    continue;
                }
            }
            let mut excluded_trees = Vec::new();
            for tree in &operation.excluded_trees {
                match resolve_item_path(directory, tree) {
                    Some(tree) => excluded_trees.push(portable_rel_path(&tree)),
                    None => {
                        facts.membership_complete = false;
                        gap(&mut facts, "unresolved_compile_item", project_path, tree);
                    }
                }
            }
            items.push(CSharpCompileItem {
                kind: match operation.kind {
                    CompileOperationKind::Include => CSharpCompileItemKind::Include,
                    CompileOperationKind::IncludeTree => CSharpCompileItemKind::IncludeTree,
                    CompileOperationKind::DefaultTree => CSharpCompileItemKind::DefaultTree,
                    CompileOperationKind::Remove => CSharpCompileItemKind::Remove,
                },
                rel_path: portable_rel_path(&path),
                excluded_trees,
            });
        }
        // Only SDK projects receive their references' references by default;
        // a legacy project's direct references still reach it.
        if !transitive_flow {
            gap(
                &mut facts,
                "unproven_transitive_reference_flow",
                project_path,
                if project.sdk_project {
                    "DisableTransitiveProjectReferences is set"
                } else {
                    "a non-SDK project's transitive reference flow is not modeled"
                },
            );
        }
        // A mutation can withdraw or change any reference of the project,
        // wherever that reference was written.
        let mut references_complete = parsed_references_complete && !references_mutated;
        let mut references = Vec::new();
        if references_mutated {
            raw_references.clear();
        }
        for (written_in, raw) in raw_references {
            match resolve_item_path(directory, raw).map(|path| portable_rel_path(&path)) {
                Some(target) if project_paths.contains(target.as_str()) => {
                    if !references.contains(&target) {
                        references.push(target);
                    }
                }
                // A reference outside the selected C# projects (missing, out
                // of the workspace, over the cap, or another language) can
                // still forward C# references transitively.
                _ => {
                    references_complete = false;
                    gap(&mut facts, "unresolved_project_reference", written_in, raw);
                }
            }
        }
        facts.compilations.push(CSharpCompilationFact {
            project_path: Some(project_path.to_owned()),
            items,
            references,
            references_complete,
            transitive_flow,
            metadata: derive_metadata(
                project_path,
                project,
                &chain,
                body_start,
                metadata_chain_complete,
                &mut facts.gaps,
            ),
        });
    }
    facts
}

/// Ordered configuration items; these are MSBuild values, not C# source syntax.
#[derive(Debug)]
struct MetadataOperation {
    item: String,
    target: String,
    remove: bool,
    alias: Option<String>,
    is_static: bool,
}

fn metadata_operation(
    item: &str,
    attributes: &[(String, String)],
    conditioned: bool,
) -> Option<MetadataOperation> {
    if conditioned
        || attributes.iter().any(|(name, value)| {
            !static_property_value(value)
                || !["Include", "Remove", "Static", "Alias", "Label"]
                    .iter()
                    .any(|allowed| name.eq_ignore_ascii_case(allowed))
        })
    {
        return None;
    }
    let include = attribute(attributes, "Include");
    let remove = attribute(attributes, "Remove");
    if include.is_some() == remove.is_some() {
        return None;
    }
    let target = include.or(remove)?.trim();
    let alias = attribute(attributes, "Alias").map(str::to_owned);
    let is_static = match attribute(attributes, "Static") {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        _ => return None,
    };
    let identifier = |name: &str| {
        let mut chars = name.strip_prefix('@').unwrap_or(name).chars();
        chars
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_alphabetic())
            && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
    };
    if target.is_empty()
        || target.contains(['*', '?', ';'])
        || (item == "using" && !target.split('.').all(identifier))
        || alias.as_deref().is_some_and(|alias| !identifier(alias))
        || (is_static && alias.is_some())
        || (item == "internalsvisibleto" && (alias.is_some() || is_static))
    {
        return None;
    }
    Some(MetadataOperation {
        item: item.to_owned(),
        target: target.to_owned(),
        remove: remove.is_some(),
        alias,
        is_static,
    })
}

fn derive_metadata(
    project_path: &str,
    project: &ParsedProject,
    chain: &[(&str, &ParsedProject)],
    body_start: usize,
    chain_complete: bool,
    gaps: &mut Vec<CSharpCompilationGap>,
) -> CSharpCompilationMetadata {
    use brokk_bifrost_csharp::compilation::{ImplicitUsingCondition, SDK_IMPLICIT_USINGS};
    let mut result = CSharpCompilationMetadata {
        assembly_name: Path::new(project_path)
            .file_stem()
            .and_then(|name| name.to_str())
            .map(str::to_owned),
        global_usings_complete: chain_complete,
        internals_visible_to_complete: chain_complete,
        ..Default::default()
    };
    let mut properties = HashMap::default();
    for (_, fragment) in chain {
        properties.extend(
            fragment
                .properties
                .metadata
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_deref())),
        );
    }
    let frameworks = properties
        .get("targetframework")
        .filter(|value| value.is_none_or(|value| !value.is_empty()))
        .or_else(|| properties.get("targetframeworks"));
    let mut gap = |code: &str, path: &str, evidence: String| {
        gaps.push(CSharpCompilationGap {
            code: code.to_owned(),
            path: path.to_owned(),
            evidence,
        })
    };
    let envelope_complete =
        chain_complete && chain.iter().all(|(_, fragment)| fragment.metadata_complete);
    if !envelope_complete {
        result.global_usings_complete = false;
        result.internals_visible_to_complete = false;
        result.assembly_name = None;
        gap(
            "unresolved_compilation_metadata",
            project_path,
            "an unsupported configuration shape can change compilation metadata".to_owned(),
        );
    }
    if let Some(value) = properties.get("assemblyname") {
        match value {
            Some(value) if !value.is_empty() => result.assembly_name = Some((*value).to_owned()),
            Some(_) => {} // The SDK's empty-name default is MSBuildProjectName.
            None => {
                result.assembly_name = None;
                gap(
                    "unresolved_assembly_name",
                    project_path,
                    "AssemblyName has a dynamic value or condition".to_owned(),
                );
            }
        }
    }
    if !envelope_complete {
        result.assembly_name = None;
    }
    let mut sdk_rows = Vec::new();
    for sdk in &project.sdks {
        match SDK_IMPLICIT_USINGS
            .iter()
            .find(|(name, _)| sdk.eq_ignore_ascii_case(name))
        {
            Some(row) => sdk_rows.push(row),
            None => {
                result.global_usings_complete = false;
                result.internals_visible_to_complete = false;
                result.assembly_name = None;
                gap(
                    "unknown_implicit_usings_sdk",
                    project_path,
                    format!("unmodeled SDK {sdk}"),
                );
            }
        }
    }
    let implicit = match properties.get("implicitusings") {
        None => false,
        Some(Some(value)) => {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("enable")
        }
        Some(None) => {
            result.global_usings_complete = false;
            gap(
                "unresolved_global_usings",
                project_path,
                "ImplicitUsings has a dynamic value or condition".to_owned(),
            );
            false
        }
    };
    // .NET 10 Razor targets can add a using before GenerateGlobalUsings,
    // based on .razor inputs this configuration-only evaluator does not see.
    let uses_razor = project.sdks.iter().any(|sdk| {
        [
            "Microsoft.NET.Sdk.Razor",
            "Microsoft.NET.Sdk.Web",
            "Microsoft.NET.Sdk.BlazorWebAssembly",
        ]
        .iter()
        .any(|name| sdk.eq_ignore_ascii_case(name))
    });
    let targeting_net10 = frameworks.and_then(|value| *value).is_some_and(|value| {
        value.split(';').any(|tfm| {
            let tfm = tfm.trim().to_ascii_lowercase();
            tfm.strip_prefix("net")
                .filter(|version| version.contains('.'))
                .and_then(|version| version.split('.').next())
                .and_then(|version| version.parse::<u32>().ok())
                .is_some_and(|version| version >= 10)
        })
    });
    let embedded_using_disabled = match properties.get("includeembeddedvalidationglobalusing") {
        Some(Some(value)) if !value.is_empty() => !value.eq_ignore_ascii_case("true"),
        Some(None) => false,
        _ => properties
            .get("generateembeddedvalidatabletypeattribute")
            .is_some_and(|value| {
                value.is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("true"))
            }),
    };
    if uses_razor && targeting_net10 && !embedded_using_disabled {
        result.global_usings_complete = false;
        gap("unresolved_global_usings", project_path,
            ".NET 10 Razor _AddEmbeddedValidationAttribute can add Microsoft.Extensions.Validation.Embedded based on unevaluated Razor inputs".to_owned());
    }
    let mut implicit_usings = Vec::<CSharpGlobalUsing>::new();
    let make_implicit = |target: &str| {
        CSharpGlobalUsing(
            "namespace".to_owned(),
            target.split('.').map(str::to_owned).collect(),
            None,
            "implicit".to_owned(),
        )
    };
    if implicit && !sdk_rows.is_empty() {
        // Inferred TargetFrameworkIdentifier participates in the SDK item
        // condition after MSBuild's property pass. Mixed inner builds do not
        // establish one compilation-wide list.
        let framework = match properties.get("targetframeworkidentifier") {
            Some(Some(value)) if !value.is_empty() => {
                Some(value.eq_ignore_ascii_case(".NETFramework"))
            }
            Some(None) => None,
            _ => {
                match frameworks {
                    Some(None) => None,
                    Some(Some(value)) if !value.is_empty() => {
                        let mut kinds = value.split(';').map(|tfm| {
                            let tfm = tfm.trim().to_ascii_lowercase();
                            if tfm.starts_with("netstandard")
                                || tfm.starts_with("netcoreapp")
                                || tfm.starts_with("net") && tfm.contains('.')
                            {
                                Some(false)
                            } else if tfm.strip_prefix("net").is_some_and(|version| {
                                !version.is_empty() && version.bytes().all(|ch| ch.is_ascii_digit())
                            }) {
                                Some(true)
                            } else {
                                None
                            }
                        });
                        let first = kinds.next().flatten();
                        if kinds.all(|kind| kind == first) {
                            first
                        } else {
                            None
                        }
                    }
                    // An unset framework identifier compares unequal to .NETFramework.
                    _ => Some(false),
                }
            }
        };
        for (target, condition) in SDK_IMPLICIT_USINGS[0].1 {
            if *condition == ImplicitUsingCondition::NotNetFramework {
                if framework.is_none() {
                    result.global_usings_complete = false;
                    gap("unresolved_global_usings", project_path, "TargetFrameworkIdentifier does not establish the System.Net.Http condition".to_owned());
                }
                if framework != Some(false) {
                    continue;
                }
            }
            let property = match condition {
                ImplicitUsingCondition::WindowsForms => Some("usewindowsforms"),
                ImplicitUsingCondition::WpfRemove => Some("usewpf"),
                _ => None,
            };
            if let Some(property) = property {
                match properties.get(property) {
                    Some(None) => {
                        result.global_usings_complete = false;
                        gap(
                            "unresolved_global_usings",
                            project_path,
                            format!("{property} has a dynamic value or condition"),
                        );
                        continue;
                    }
                    Some(Some(value)) if value.eq_ignore_ascii_case("true") => {}
                    _ => continue,
                }
            }
            if *condition == ImplicitUsingCondition::WpfRemove {
                implicit_usings.retain(|using| using.1.join(".") != *target);
            } else {
                implicit_usings.push(make_implicit(target));
            }
        }
        for row in sdk_rows {
            if row.0.eq_ignore_ascii_case("Microsoft.NET.Sdk") {
                continue;
            }
            match properties.get("language") {
                Some(None) => {
                    result.global_usings_complete = false;
                    gap(
                        "unresolved_global_usings",
                        project_path,
                        "Language has a dynamic value or condition".to_owned(),
                    );
                    continue;
                }
                Some(Some(language)) if !language.eq_ignore_ascii_case("C#") => continue,
                _ => {}
            }
            let mut extra = row.1;
            if row.0.eq_ignore_ascii_case("Microsoft.NET.Sdk.Web") {
                // Web/Sdk/Sdk.props delegates browser targets to BlazorWasmSdk.
                let browser = match frameworks {
                    Some(None) => None,
                    Some(Some(value)) => {
                        let mut platforms = value.split(';').map(|tfm| {
                            tfm.split('-').nth(1).is_some_and(|platform| {
                                platform
                                    .chars()
                                    .take_while(|ch| !ch.is_ascii_digit())
                                    .collect::<String>()
                                    .eq_ignore_ascii_case("browser")
                            })
                        });
                        let first = platforms.next().unwrap_or(false);
                        platforms.all(|platform| platform == first).then_some(first)
                    }
                    None => Some(false),
                };
                match browser {
                    Some(true) => {
                        extra = SDK_IMPLICIT_USINGS
                            .iter()
                            .find(|(sdk, _)| *sdk == "Microsoft.NET.Sdk.BlazorWebAssembly")
                            .expect("Blazor SDK table row")
                            .1
                    }
                    Some(false) => {}
                    None => {
                        result.global_usings_complete = false;
                        gap(
                            "unresolved_global_usings",
                            project_path,
                            "TargetFramework does not establish the Web SDK browser condition"
                                .to_owned(),
                        );
                        continue;
                    }
                }
            }
            implicit_usings.extend(extra.iter().map(|(target, _)| make_implicit(target)));
        }
    }
    for (index, (path, fragment)) in chain.iter().enumerate() {
        if index == body_start {
            result.global_usings.append(&mut implicit_usings);
        }
        for (item, evidence) in &fragment.metadata_gaps {
            if item == "internalsvisibleto" {
                result.internals_visible_to_complete = false;
                gap("unresolved_internals_visible_to", path, evidence.clone());
            } else {
                result.global_usings_complete = false;
                gap("unresolved_global_usings", path, evidence.clone());
            }
        }
        for operation in &fragment.metadata_operations {
            if operation.item == "internalsvisibleto" {
                if operation.remove {
                    result
                        .internals_visible_to
                        .retain(|name| !name.eq_ignore_ascii_case(&operation.target));
                } else {
                    result.internals_visible_to.push(operation.target.clone());
                }
            } else if operation.remove {
                result
                    .global_usings
                    .retain(|using| !using.1.join(".").eq_ignore_ascii_case(&operation.target));
            } else {
                result.global_usings.push(CSharpGlobalUsing(
                    if operation.alias.is_some() {
                        "alias"
                    } else if operation.is_static {
                        "static"
                    } else {
                        "namespace"
                    }
                    .to_owned(),
                    operation.target.split('.').map(str::to_owned).collect(),
                    operation.alias.clone(),
                    "item".to_owned(),
                ));
            }
        }
    }
    result
}

/// The configuration input named `name` in `directory` or its nearest
/// ancestor within the workspace, as MSBuild finds a Directory.Build file.
fn nearest_input<'a>(
    parsed: &HashMap<&'a str, Option<ParsedProject>>,
    directory: &Path,
    name: &str,
) -> Option<&'a str> {
    directory.ancestors().find_map(|ancestor| {
        let candidate = portable_rel_path(&ancestor.join(name));
        parsed
            .get_key_value(candidate.as_str())
            .map(|(path, _)| *path)
    })
}

/// Append `path` to `chain`, preceded by the files it imports. Imports that
/// leave the inputs, cycle or nest too deeply are recorded in `gaps`.
fn expand_chain<'a>(
    parsed: &'a HashMap<&'a str, Option<ParsedProject>>,
    path: &'a str,
    depth: usize,
    chain: &mut Vec<(&'a str, &'a ParsedProject)>,
    gaps: &mut Vec<(&'a str, String)>,
) {
    if depth > MAX_IMPORT_DEPTH {
        gaps.push((path, format!("imports nest deeper than {MAX_IMPORT_DEPTH}")));
        return;
    }
    if chain.iter().any(|(chained, _)| *chained == path) {
        gaps.push((path, "the import chain revisits this file".to_owned()));
        return;
    }
    let Some((path, Some(fragment))) = parsed
        .get_key_value(path)
        .map(|(path, fragment)| (*path, fragment.as_ref()))
    else {
        gaps.push((
            path,
            "imported file is not a readable configuration input".to_owned(),
        ));
        return;
    };
    let directory = Path::new(path).parent().unwrap_or(Path::new(""));
    for import in &fragment.imports {
        match resolve_item_path(directory, import)
            .map(|resolved| portable_rel_path(&resolved))
            .and_then(|resolved| parsed.get_key_value(resolved.as_str()).map(|(key, _)| *key))
        {
            Some(imported) => expand_chain(parsed, imported, depth + 1, chain, gaps),
            None => gaps.push((
                path,
                format!("import {import} is not a configuration input"),
            )),
        }
    }
    chain.push((path, fragment));
}

/// Workspace-relative path text as the store spells it.
fn portable_rel_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

impl CSharpAnalyzer {
    /// The compilation rules this generation's selected revision publishes.
    /// `Some(None)` when the revision has no valid selection; `None` after a
    /// store error, which is recorded.
    fn selected_compilations(&self) -> Option<Option<SelectedCSharpCompilations<'_>>> {
        let snapshots = self.inner.selected_workspace_snapshots();
        let Some(snapshot) = snapshots.get(csharp_compilation::STORAGE_LANGUAGE) else {
            return Some(None);
        };
        let store = self.inner.analyzer_store();
        // Rows describe the selected disk configuration. A request whose
        // overlay changes a configuration input needs a membership they
        // cannot state.
        let overlay = self.record_membership_read(store.native_configuration_overlay_mismatch(
            self.inner.project(),
            &snapshots,
            csharp_compilation::STORAGE_LANGUAGE,
            Language::CSharp,
            &CancellationToken::new(),
        ))?;
        if overlay != NativeConfigurationOverlayAuthority::Current {
            return Some(None);
        }
        self.inner.store_query_or_record(
            |sink| sink.push(self.inner.scope_read_key()),
            store.selected_csharp_compilations(snapshot),
            "reading selected C# compilation membership",
        )
    }

    fn record_membership_read<T>(
        &self,
        result: Result<T, brokk_bifrost_analysis::analyzer::store::StoreError>,
    ) -> Option<T> {
        self.inner.store_query_or_record(
            |sink| sink.push(self.inner.scope_read_key()),
            result,
            "reading C# compilation membership",
        )
    }

    /// Where `candidate`'s source sits relative to the compilation holding
    /// `reference`. `None` after a recorded store error.
    pub(crate) fn compilation_visibility(
        &self,
        reference: &ProjectFile,
        candidate: &ProjectFile,
    ) -> Option<CSharpCompilationVisibility> {
        let Some(selection) = self.selected_compilations()? else {
            return Some(CSharpCompilationVisibility::Unresolved);
        };
        let Some(from) =
            self.record_membership_read(selection.compilations_of(&rel_path_string(reference)))?
        else {
            return Some(CSharpCompilationVisibility::Unresolved);
        };
        let Some(to) =
            self.record_membership_read(selection.compilations_of(&rel_path_string(candidate)))?
        else {
            return Some(CSharpCompilationVisibility::Unresolved);
        };
        if from.is_empty() || to.is_empty() {
            return Some(CSharpCompilationVisibility::Unresolved);
        }
        // A source compiled by several projects is one physical node for
        // several compiled instances; it has one answer only when every
        // instance agrees.
        let mut answer = None;
        let meets = |compilations: &[i64]| {
            to.iter()
                .any(|target| compilations.binary_search(target).is_ok())
        };
        for compilation in from {
            // Visible needs a proven path: proven edges, walked beyond the
            // direct ones only through proven transitive flow. Not visible
            // needs the opposite proof: outside every edge's reach, with
            // every reached project's references known.
            let visible = self.record_membership_read(selection.visible_closure(compilation))?;
            let instance = if meets(&visible) {
                CSharpCompilationVisibility::Visible
            } else {
                let (reached, complete) =
                    self.record_membership_read(selection.referenced_closure(compilation))?;
                if complete && !meets(&reached) {
                    CSharpCompilationVisibility::NotVisible
                } else {
                    CSharpCompilationVisibility::Unresolved
                }
            };
            if answer.is_some_and(|answer| answer != instance) {
                return Some(CSharpCompilationVisibility::Unresolved);
            }
            answer = Some(instance);
        }
        answer
    }

    /// For each of `files`, the global-using sources compiled with it, and
    /// whether that answer is complete. `None` after a recorded store error.
    pub(crate) fn global_using_dependencies(
        &self,
        files: &[ProjectFile],
        global_using_files: &[ProjectFile],
    ) -> Option<(HashMap<ProjectFile, HashSet<ProjectFile>>, bool)> {
        let Some(selection) = self.selected_compilations()? else {
            return Some((HashMap::default(), false));
        };
        // The proof boundary: membership complete, every explicit include
        // selected, and at most one project. An SDK default glob also
        // compiles sources the listing omits (ignored generated files), and
        // ignored project files are never inputs; no recorded input proves
        // either absent. One project (or none) is the boundary the earlier
        // compilation index already certified and is kept; several projects
        // were never certified and stay incomplete.
        let mut complete = selection.membership_complete()
            && self.record_membership_read(selection.includes_selected())?
            && self.record_membership_read(selection.project_count())? <= 1;
        if !complete && brokk_bifrost_core::profiling::enabled() {
            brokk_bifrost_core::profiling::note(format!(
                "csharp compilation membership unproven: {:?}",
                self.record_membership_read(selection.gaps())?
            ));
        }
        let mut compilation_of = |file: &ProjectFile| -> Option<Option<i64>> {
            let compilations =
                self.record_membership_read(selection.compilations_of(&rel_path_string(file)))?;
            Some(match compilations.as_deref() {
                Some([compilation]) => Some(*compilation),
                // Unproven, uncompiled, or one physical node for several
                // compiled instances.
                _ => {
                    complete = false;
                    None
                }
            })
        };
        let mut globals = Vec::new();
        for global in global_using_files {
            if let Some(compilation) = compilation_of(global)? {
                globals.push((global, compilation));
            }
        }
        let mut by_file = HashMap::default();
        for file in files {
            let Some(compilation) = compilation_of(file)? else {
                continue;
            };
            let dependencies = globals
                .iter()
                .filter(|(_, global)| *global == compilation)
                .map(|(global, _)| (*global).clone())
                .collect::<HashSet<_>>();
            if !dependencies.is_empty() {
                by_file.insert(file.clone(), dependencies);
            }
        }
        Some((by_file, complete))
    }

    /// Identity of the build configuration that the compilation graph reads.
    ///
    /// Snapshot freshness checks ask for it on every request, including when
    /// the graph itself is partial and so is rebuilt per request instead of
    /// memoized. The identity is one fixed-size digest, so it is memoized for
    /// the generation on its own. An unknown identity (incomplete source
    /// inventory, a failed listing, a capped or unreadable configuration
    /// file) publishes nothing, and the next lookup retries.
    pub(crate) fn compilation_config_digest(&self) -> Option<StableDigest> {
        self.memo_caches
            .compilation_config_digest
            .get_or_try_build_on_dedicated_pool(|| {
                let inventory =
                    brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer::source_file_inventory(
                        &self.inner,
                    );
                if !inventory.complete {
                    return Err(());
                }
                let project = self.inner.project();
                let workspace_files = project.all_files_shared().map_err(drop)?;
                read_config_digest(project, &workspace_files).ok_or(())
            })
            .ok()
            .map(|digest| *digest)
    }
}

#[derive(Debug)]
struct ParsedProject {
    sdks: Vec<String>,
    metadata_operations: Vec<MetadataOperation>,
    metadata_complete: bool,
    metadata_gaps: Vec<(String, String)>,
    /// A .NET SDK project, which compiles C# with default Compile items.
    sdk_project: bool,
    /// A traversal or no-targets SDK project: no compilation at all.
    compiles_nothing: bool,
    operations: Vec<CompileOperation>,
    /// Whether the Compile items and default-item properties are all in
    /// supported static shapes.
    complete: bool,
    /// Raw `Include` paths of the ProjectReference items whose shape and
    /// metadata prove a plain compile reference, in order.
    references: Vec<String>,
    /// Whether `references` are all of the project's ProjectReference items.
    references_complete: bool,
    /// Whether a ProjectReference Remove, Update or item definition can
    /// withdraw or change references written anywhere in the chain.
    references_mutated: bool,
    /// Whether no property changes the SDK's default transitive flow of
    /// references into this project.
    transitive_flow: bool,
    /// Files this one imports first, relative to its own directory, in order.
    imports: Vec<String>,
    /// The file's own default-item settings, for combining with the files
    /// imported around a project.
    properties: DefaultItemProperties,
}

/// The last unconditioned value a file (or a chain prefix) assigns to each
/// property the SDK default Compile item reads; `None` when unassigned.
#[derive(Debug, Default, Clone)]
struct DefaultItemProperties {
    enable_default_items: Option<String>,
    enable_default_compile_items: Option<String>,
    base_output_path: Option<String>,
    base_intermediate_output_path: Option<String>,
    // Some(None) is an assignment whose value or condition is not statically known.
    metadata: HashMap<String, Option<String>>,
}

impl DefaultItemProperties {
    fn slot(&mut self, kind: PropertyKind) -> Option<&mut Option<String>> {
        match kind {
            PropertyKind::EnableDefaultItems => Some(&mut self.enable_default_items),
            PropertyKind::EnableDefaultCompileItems => Some(&mut self.enable_default_compile_items),
            PropertyKind::BaseOutputPath => Some(&mut self.base_output_path),
            PropertyKind::BaseIntermediateOutputPath => {
                Some(&mut self.base_intermediate_output_path)
            }
            PropertyKind::Unsupported | PropertyKind::ReferenceFlow | PropertyKind::Metadata(_) => {
                None
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.enable_default_items.is_none()
            && self.enable_default_compile_items.is_none()
            && !self.sets_output_roots()
    }

    fn sets_output_roots(&self) -> bool {
        self.base_output_path.is_some() || self.base_intermediate_output_path.is_some()
    }

    /// Apply a later file's assignments.
    fn overlay(&mut self, later: &Self) {
        self.metadata.extend(later.metadata.clone());
        for (value, later) in [
            (&mut self.enable_default_items, &later.enable_default_items),
            (
                &mut self.enable_default_compile_items,
                &later.enable_default_compile_items,
            ),
            (&mut self.base_output_path, &later.base_output_path),
            (
                &mut self.base_intermediate_output_path,
                &later.base_intermediate_output_path,
            ),
        ] {
            if later.is_some() {
                value.clone_from(later);
            }
        }
    }

    /// What Sdk.targets does before Directory.Build.targets: an unset or
    /// empty `EnableDefault*Items` becomes `true`
    /// (Microsoft.NET.Sdk.DefaultItems.targets), and the default excludes
    /// take the build output roots then in effect, `bin` and `obj` when
    /// unset or empty (Microsoft.Common.props, Microsoft.NET.DefaultOutputPaths.targets).
    /// Returns those roots.
    fn fill_sdk_defaults(&mut self) -> (String, String) {
        for value in [
            &mut self.enable_default_items,
            &mut self.enable_default_compile_items,
        ] {
            if value.as_deref().is_none_or(str::is_empty) {
                *value = Some("true".to_owned());
            }
        }
        let root = |value: &Option<String>, default: &str| match value.as_deref() {
            None | Some("") => default.to_owned(),
            Some(value) => value.to_owned(),
        };
        (
            root(&self.base_output_path, "bin"),
            root(&self.base_intermediate_output_path, "obj"),
        )
    }
}

/// A ProjectReference element whose children are still being read. It
/// becomes an edge only if none of them is unsupported metadata.
#[derive(Debug)]
struct PendingReference {
    depth: usize,
    path: String,
    supported: bool,
}

#[derive(Debug, Clone)]
struct CompileOperation {
    kind: CompileOperationKind,
    /// A file, or for [`CompileOperationKind::IncludeTree`] a directory.
    path: String,
    /// An `Exclude` filters only this `Include` item; it is not a removal
    /// from the compilation's pre-existing SDK default items.
    exclude: Option<String>,
    /// For a tree include, directories its `Exclude` globs leave out.
    excluded_trees: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum CompileOperationKind {
    Include,
    /// `<dir>/**/*.cs`: every C# source below a directory.
    IncludeTree,
    /// The SDK default Compile item of the project directory.
    DefaultTree,
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
    Metadata(&'static str),
    EnableDefaultItems,
    EnableDefaultCompileItems,
    BaseOutputPath,
    BaseIntermediateOutputPath,
    /// A property that changes the default Compile item or which files the
    /// evaluation imports in a way this parser does not model.
    Unsupported,
    /// `DisableTransitiveProjectReferences` changes which referenced
    /// projects' references a compilation sees.
    ReferenceFlow,
}

fn parse_project(source: &str) -> ParsedProject {
    // Untrimmed: a property value is trimmed once, whole, so whitespace next
    // to a character reference inside it survives.
    let mut reader = Reader::from_str(source);
    let mut stack = Vec::<ElementFrame>::new();
    let mut operations = Vec::new();
    let mut metadata_operations = Vec::new();
    let mut metadata_gaps = Vec::new();
    let mut metadata_imports_complete = true;
    let mut references = Vec::new();
    let mut references_complete = true;
    let mut references_mutated = false;
    let mut transitive_flow = true;
    let mut imports = Vec::new();
    let mut pending_reference = None::<PendingReference>;
    let mut sdks = Vec::<String>::new();
    let mut properties = DefaultItemProperties::default();
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
        let (element, is_empty) = match event {
            Event::Start(start) => (start, false),
            Event::Empty(empty) => (empty, true),
            // Every piece of character data is held to XML 1.0 whether or not
            // a membership property captures it: a parser that certifies
            // membership must not accept a malformed configuration file.
            Event::Text(text) => {
                match text.xml10_content() {
                    Ok(text) if is_xml_text(&text) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.text.push_str(&text);
                        }
                    }
                    _ => complete = false,
                }
                buffer.clear();
                continue;
            }
            Event::GeneralRef(reference) => {
                // A character reference or one of XML's predefined entities;
                // a project declares no others this parser could expand.
                let expansion = match reference.resolve_char_ref() {
                    Ok(Some(character)) => Some(character.to_string()),
                    Ok(None) => reference.decode().ok().and_then(|name| {
                        quick_xml::escape::resolve_xml_entity(&name).map(str::to_owned)
                    }),
                    Err(_) => None,
                };
                match expansion {
                    Some(text) if is_xml_text(&text) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.text.push_str(&text);
                        }
                    }
                    _ => complete = false,
                }
                buffer.clear();
                continue;
            }
            Event::CData(text) => {
                match text.decode() {
                    Ok(text) if is_xml_text(&text) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.text.push_str(&text);
                        }
                    }
                    _ => complete = false,
                }
                buffer.clear();
                continue;
            }
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) | Event::DocType(_) => {
                // Their raw bytes are a slice of the UTF-8 source.
                if !std::str::from_utf8(&buffer).is_ok_and(is_xml_text) {
                    complete = false;
                }
                buffer.clear();
                continue;
            }
            Event::End(end) => {
                if capture
                    .as_ref()
                    .is_some_and(|capture| capture.depth == stack.len())
                {
                    let property = capture.take().expect("capture was checked");
                    if is_xml_text(&property.text) {
                        assign_property(
                            property.kind,
                            property.conditioned,
                            &property.text,
                            &mut properties,
                            &mut transitive_flow,
                            &mut complete,
                        );
                    } else {
                        complete = false;
                    }
                }
                if pending_reference
                    .as_ref()
                    .is_some_and(|pending| pending.depth == stack.len())
                {
                    let pending = pending_reference.take().expect("pending was checked");
                    if pending.supported {
                        references.push(pending.path);
                    }
                }
                let end_name = msbuild_name(end.name().as_ref());
                if stack
                    .pop()
                    .is_none_or(|frame| end_name.as_deref() != Some(frame.name.as_str()))
                {
                    complete = false;
                    break;
                }
                buffer.clear();
                continue;
            }
            Event::Eof => break,
        };
        nodes = nodes.saturating_add(1);
        if nodes > MAX_XML_NODES || (!is_empty && stack.len() >= MAX_XML_DEPTH) {
            complete = false;
            break;
        }
        let Some(name) = msbuild_name(element.name().as_ref()) else {
            complete = false;
            break;
        };
        let Some(attributes) = element_attributes(&reader, &element) else {
            complete = false;
            break;
        };
        if let Some(capture) = capture.as_mut() {
            // XML children in a scalar property are not a statically known value.
            capture.conditioned = true;
            complete = false;
        }
        let parent = stack.last().map(|frame| frame.name.as_str());
        let conditioned = stack.last().is_some_and(|frame| frame.conditioned)
            || is_conditioning_element(&name, &attributes);
        if parent == Some("projectreference") && !is_supported_reference_metadata(&name) {
            references_complete = false;
            if let Some(pending) = pending_reference.as_mut() {
                pending.supported = false;
            }
        }
        // An element directly in a PropertyGroup is a property assignment.
        let is_property = parent == Some("propertygroup");
        let property = is_property.then(|| property_kind(&name)).flatten();
        let in_item_definitions = stack
            .iter()
            .any(|frame| frame.name == "itemdefinitiongroup");
        let mut reference = None;
        if !is_property && matches!(name.as_str(), "using" | "internalsvisibleto") {
            match metadata_operation(
                &name,
                &attributes,
                conditioned || in_item_definitions || !is_empty,
            ) {
                Some(operation) => metadata_operations.push(operation),
                None => metadata_gaps.push((
                    name.clone(),
                    format!("unsupported {name} item: {attributes:?}"),
                )),
            }
        }
        match name.as_str() {
            "project" | "sdk" => {
                let attribute_name = if name == "project" { "Sdk" } else { "Name" };
                if name == "project" && conditioned {
                    complete = false;
                }
                let value = attribute(&attributes, attribute_name);
                if name == "sdk"
                    && (conditioned
                        || value.is_none()
                        || attributes
                            .iter()
                            .any(|(_, value)| !static_property_value(value)))
                {
                    complete = false;
                } else if let Some(value) = value {
                    if conditioned || !static_property_value(value) {
                        complete = false;
                    } else {
                        sdks.extend(sdk_names(value));
                    }
                }
            }
            "import" => {
                let content_seen = !operations.is_empty()
                    || !references.is_empty()
                    || references_mutated
                    || !properties.is_empty()
                    || !transitive_flow;
                let metadata_seen = !metadata_operations.is_empty()
                    || !metadata_gaps.is_empty()
                    || !properties.metadata.is_empty();
                let imports_before = imports.len();
                collect_import(
                    &attributes,
                    conditioned,
                    content_seen,
                    &mut imports,
                    &mut complete,
                );
                if metadata_seen && imports.len() != imports_before {
                    metadata_imports_complete = false;
                    metadata_gaps.push(("configuration".to_owned(),
                        "an Import follows compilation metadata whose evaluation order is unmodeled".to_owned()));
                }
            }
            "compile" if !is_property => {
                collect_compile_operation(&attributes, conditioned, &mut operations, &mut complete);
            }
            "projectreference" if !is_property => {
                // A definition sets defaults for every ProjectReference; a
                // Remove or Update can withdraw or change one written
                // anywhere in the chain.
                if in_item_definitions
                    || attribute(&attributes, "Remove").is_some()
                    || attribute(&attributes, "Update").is_some()
                {
                    references_mutated = true;
                } else {
                    reference = project_reference_path(&attributes, conditioned);
                    if reference.is_none() {
                        references_complete = false;
                    }
                }
            }
            _ => {}
        }
        if is_empty {
            if let Some(kind) = property {
                assign_property(
                    kind,
                    conditioned,
                    "",
                    &mut properties,
                    &mut transitive_flow,
                    &mut complete,
                );
            }
            if let Some(path) = reference {
                references.push(path);
            }
        } else {
            stack.push(ElementFrame { name, conditioned });
            if let Some(path) = reference {
                // Child metadata can still disqualify the edge.
                pending_reference = Some(PendingReference {
                    depth: stack.len(),
                    path,
                    supported: true,
                });
            }
            if let Some(kind) = property {
                capture = Some(PropertyCapture {
                    depth: stack.len(),
                    conditioned,
                    kind,
                    text: String::new(),
                });
            }
        }
        buffer.clear();
    }
    if !stack.is_empty() || capture.is_some() {
        complete = false;
    }
    if pending_reference.is_some() {
        references_complete = false;
    }
    let metadata_complete = complete && metadata_imports_complete;
    // Only Microsoft.NET.Sdk's default Compile item is modeled. A traversal
    // or no-targets project compiles nothing; any other SDK (including the
    // Microsoft.NET.Sdk.* family, whose props add their own excludes) is
    // unmodeled.
    let sdk_project = sdks
        .iter()
        .any(|sdk| sdk.eq_ignore_ascii_case("Microsoft.NET.Sdk"));
    let is_compiles_nothing_sdk = |sdk: &String| {
        sdk.eq_ignore_ascii_case("Microsoft.Build.Traversal")
            || sdk.eq_ignore_ascii_case("Microsoft.Build.NoTargets")
    };
    let compiles_nothing = !sdks.is_empty() && sdks.iter().all(is_compiles_nothing_sdk);
    if sdks
        .iter()
        .any(|sdk| !sdk.eq_ignore_ascii_case("Microsoft.NET.Sdk") && !is_compiles_nothing_sdk(sdk))
        || (sdk_project && sdks.iter().any(is_compiles_nothing_sdk))
    {
        complete = false;
    }
    ParsedProject {
        sdks,
        metadata_operations,
        metadata_complete,
        metadata_gaps,
        sdk_project,
        compiles_nothing,
        operations,
        complete,
        references,
        references_complete,
        references_mutated,
        transitive_flow,
        imports,
        properties,
    }
}

/// An element's local name, lowercase: MSBuild compares item, property and
/// metadata names case-insensitively, and treating its element keywords the
/// same way only adds gaps.
fn msbuild_name(raw: &[u8]) -> Option<String> {
    local_xml_name(raw).map(|name| name.to_ascii_lowercase())
}

/// An `<Import>` this parser can follow: unconditioned, before any content
/// it would have to interleave with, naming a static path relative to the
/// importing file (optionally spelled `$(MSBuildThisFileDirectory)...`).
fn collect_import(
    attributes: &[(String, String)],
    conditioned: bool,
    content_seen: bool,
    imports: &mut Vec<String>,
    complete: &mut bool,
) {
    const THIS_FILE_DIRECTORY: &str = "$(MSBuildThisFileDirectory)";
    let supported_attributes = attributes
        .iter()
        .all(|(name, _)| matches!(name.as_str(), "Project" | "Label"));
    let path = attribute(attributes, "Project").map(|project| {
        let project = project.trim();
        match project.get(..THIS_FILE_DIRECTORY.len()) {
            Some(prefix) if prefix.eq_ignore_ascii_case(THIS_FILE_DIRECTORY) => {
                &project[THIS_FILE_DIRECTORY.len()..]
            }
            _ => project,
        }
    });
    match path {
        Some(path)
            if !conditioned && !content_seen && supported_attributes && static_item_path(path) =>
        {
            imports.push(path.to_owned());
        }
        _ => *complete = false,
    }
}

/// The SDK names an `Sdk` value lists, without versions (`Name/1.0`).
fn sdk_names(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(';')
        .map(|sdk| sdk.split('/').next().unwrap_or_default().trim())
        .filter(|sdk| !sdk.is_empty())
        .map(str::to_owned)
}

/// Whether `name` (with `attributes`) makes its contents depend on something
/// static evaluation does not decide: an explicit `Condition`, a
/// `Choose`/`When`/`Otherwise` branch, or a `Target` body, whose items and
/// properties apply only if and when the target executes.
fn is_conditioning_element(name: &str, attributes: &[(String, String)]) -> bool {
    matches!(name, "target" | "choose" | "when" | "otherwise")
        || attribute(attributes, "Condition").is_some()
}

/// How assigning the property `name` (lowercase; MSBuild property names
/// compare case-insensitively) bears on Compile membership.
fn property_kind(name: &str) -> Option<PropertyKind> {
    Some(match name {
        "includeembeddedvalidationglobalusing" => {
            PropertyKind::Metadata("includeembeddedvalidationglobalusing")
        }
        "generateembeddedvalidatabletypeattribute" => {
            PropertyKind::Metadata("generateembeddedvalidatabletypeattribute")
        }
        "language" => PropertyKind::Metadata("language"),
        "implicitusings" => PropertyKind::Metadata("implicitusings"),
        "assemblyname" => PropertyKind::Metadata("assemblyname"),
        "targetframeworkidentifier" => PropertyKind::Metadata("targetframeworkidentifier"),
        "usewpf" => PropertyKind::Metadata("usewpf"),
        "usewindowsforms" => PropertyKind::Metadata("usewindowsforms"),
        "targetframework" => PropertyKind::Metadata("targetframework"),
        "targetframeworks" => PropertyKind::Metadata("targetframeworks"),
        "enabledefaultitems" => PropertyKind::EnableDefaultItems,
        "enabledefaultcompileitems" => PropertyKind::EnableDefaultCompileItems,
        "baseoutputpath" => PropertyKind::BaseOutputPath,
        "baseintermediateoutputpath" => PropertyKind::BaseIntermediateOutputPath,
        "disabletransitiveprojectreferences" => PropertyKind::ReferenceFlow,
        // The other inputs of the SDK default Compile item and its excludes
        // (Microsoft.NET.Sdk.DefaultItems.props/.targets, the output paths
        // PublishDir derives from, the artifacts layout).
        "defaultitemexcludes"
        | "defaultexcludesinprojectfolder"
        | "defaultitemexcludesinprojectfolder"
        | "disabledefaultitemsinprojectfolder"
        | "defaultlanguagesourceextension"
        | "usingnetsdkdefaults"
        | "outputpath"
        | "publishdir"
        | "useartifactsoutput"
        | "artifactspath" => PropertyKind::Unsupported,
        // The import hooks of Microsoft.Common.props/.targets and the SDK's
        // Sdk.props/.targets (`ImportDirectoryBuildProps`,
        // `CustomBeforeMicrosoftCommonTargets`, `DirectoryBuildPropsPath`,
        // `AlternateCommonProps`, `LanguageTargets`, `NuGetPropsFile`, ...)
        // move, add or disable imported files.
        _ if name.starts_with("import")
            || name.starts_with("custombefore")
            || name.starts_with("customafter")
            || [
                "props",
                "targets",
                "propspath",
                "targetspath",
                "propsfile",
                "targetsfile",
            ]
            .iter()
            .any(|suffix| name.ends_with(suffix)) =>
        {
            PropertyKind::Unsupported
        }
        _ => return None,
    })
}

/// Record one assignment of a property of `kind` with the value `text`.
fn assign_property(
    kind: PropertyKind,
    conditioned: bool,
    text: &str,
    properties: &mut DefaultItemProperties,
    transitive_flow: &mut bool,
    complete: &mut bool,
) {
    if let PropertyKind::Metadata(name) = kind {
        let value = text.trim();
        properties.metadata.insert(
            name.to_owned(),
            (!conditioned && static_property_value(value)).then(|| value.to_owned()),
        );
        return;
    }
    if matches!(kind, PropertyKind::ReferenceFlow) {
        // Any setting, conditioned or not, may withhold the references'
        // references from this project.
        *transitive_flow = false;
        return;
    }
    match properties.slot(kind) {
        Some(slot) if !conditioned => *slot = Some(text.trim().to_owned()),
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
        if let Some(directory) = tree_glob(path) {
            // A tree include's Exclude may only leave out whole trees.
            let mut excluded_trees = Vec::new();
            for pattern in exclude.into_iter().flat_map(|exclude| exclude.split(';')) {
                let pattern = pattern.trim();
                if pattern.is_empty() {
                    continue;
                }
                match tree_glob(pattern) {
                    Some(excluded) => excluded_trees.push(excluded),
                    None => {
                        *complete = false;
                        return;
                    }
                }
            }
            operations.push(CompileOperation {
                kind: CompileOperationKind::IncludeTree,
                path: directory,
                exclude: None,
                excluded_trees,
            });
            return;
        }
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
            excluded_trees: Vec::new(),
        });
    } else if let Some(path) = remove {
        if static_item_path(path) {
            operations.push(CompileOperation {
                kind: CompileOperationKind::Remove,
                path: path.to_owned(),
                exclude: None,
                excluded_trees: Vec::new(),
            });
        } else {
            *complete = false;
        }
    }
}

/// The directory of a recursive C# glob `<dir>/**/*.cs` (`**/*.cs` for the
/// item's own directory), or `None` for any other pattern.
fn tree_glob(pattern: &str) -> Option<String> {
    let pattern = pattern.trim().replace('\\', "/");
    let directory = if pattern.eq_ignore_ascii_case("**/*.cs") {
        ""
    } else {
        let split = pattern.len().checked_sub("/**/*.cs".len())?;
        let (directory, glob) = pattern.split_at(split);
        if !glob.eq_ignore_ascii_case("/**/*.cs") {
            return None;
        }
        directory
    };
    (directory.is_empty() || static_item_path(directory)).then(|| directory.to_owned())
}

/// Item metadata that does not change whether or how a referenced project's
/// declarations reach this compilation. Anything else (`Aliases`,
/// `ReferenceOutputAssembly`, `PrivateAssets`, `SetTargetFramework`, ...) is
/// unsupported, not ignored.
fn is_supported_reference_metadata(name: &str) -> bool {
    ["Name", "Project", "Private"]
        .iter()
        .any(|supported| name.eq_ignore_ascii_case(supported))
}

/// The `Include` path of a ProjectReference whose own attributes prove a
/// plain compile reference, or `None` when it is conditioned, dynamic or
/// carries unsupported metadata.
fn project_reference_path(attributes: &[(String, String)], conditioned: bool) -> Option<String> {
    if conditioned
        || attributes.iter().any(|(name, _)| {
            !name.eq_ignore_ascii_case("Include") && !is_supported_reference_metadata(name)
        })
    {
        return None;
    }
    attribute(attributes, "Include")
        .filter(|path| static_item_path(path))
        .map(str::to_owned)
}

/// Whether `text` holds only XML 1.0 characters
/// (<https://www.w3.org/TR/REC-xml/#NT-Char>). A character reference to any
/// other is not well-formed (the Legal Character constraint), and quick-xml
/// checks only that a reference names a Unicode scalar value.
fn is_xml_text(text: &str) -> bool {
    text.chars().all(|character| {
        matches!(
            character,
            '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
        )
    })
}

pub(super) fn element_attributes(
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
            is_xml_text(&value).then_some((name, value))
        })
        .collect()
}

/// The value of the attribute `name`, compared case-insensitively.
pub(super) fn attribute<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
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

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
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

    use crate::analyzer::csharp::compilation::*;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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

    /// The analyzer of `files`, whose build publishes the membership rows.
    fn analyzed(
        files: &[(&str, &str)],
    ) -> (
        tempfile::TempDir,
        Arc<TestProject>,
        Vec<ProjectFile>,
        CSharpAnalyzer,
    ) {
        let (root, project, analyzed) = fixture(files);
        let project = Arc::new(project);
        let analyzer = CSharpAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>);
        (root, project, analyzed, analyzer)
    }

    fn global_dependencies(
        analyzer: &CSharpAnalyzer,
        files: &[ProjectFile],
        global: &ProjectFile,
    ) -> (HashMap<ProjectFile, HashSet<ProjectFile>>, bool) {
        analyzer
            .global_using_dependencies(files, std::slice::from_ref(global))
            .expect("membership reads succeed")
    }

    /// Evaluated configuration crosses the producer/SQLite/selected-reader boundary.
    #[test]
    fn compilation_metadata_round_trips_configuration_golden() {
        use std::fmt::Write;
        let fixture_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compilation-metadata");
        let projects = [
            "App",
            "Default",
            "Framework",
            "Mixed",
            "Web",
            "Browser",
            "MixedWeb",
            "Worker",
            "Razor",
            "Razor10",
            "Razor10Disabled",
            "Blazor",
            "Desktop",
            "Unknown",
            "Conditional",
        ];
        let mut owned = vec![
            (
                "Directory.Build.props".to_owned(),
                fs::read_to_string(fixture_root.join("Directory.Build.props")).unwrap(),
            ),
            (
                "Directory.Build.targets".to_owned(),
                fs::read_to_string(fixture_root.join("Directory.Build.targets")).unwrap(),
            ),
        ];
        for name in projects {
            let path = format!("{name}/{name}.csproj");
            owned.push((
                path.clone(),
                fs::read_to_string(fixture_root.join(path)).unwrap(),
            ));
            owned.push((format!("{name}/Source.cs"), "class Source {}".to_owned()));
        }
        let files = owned
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let (_root, _project, _files, analyzer) = analyzed(&files);
        let selection = analyzer
            .selected_compilations()
            .unwrap()
            .expect("published compilation set");
        let mut rendered = String::new();
        for name in projects {
            let metadata = selection
                .metadata(Some(&format!("{name}/{name}.csproj")))
                .unwrap()
                .expect("selected compilation");
            writeln!(rendered, "{name}: assembly={:?}", metadata.assembly_name).unwrap();
            writeln!(
                rendered,
                "  usings complete={}",
                metadata.global_usings_complete
            )
            .unwrap();
            for using in metadata.global_usings {
                writeln!(
                    rendered,
                    "    {} {} alias={:?} origin={}",
                    using.0,
                    using.1.join("."),
                    using.2,
                    using.3
                )
                .unwrap();
            }
            writeln!(
                rendered,
                "  friends complete={}: {:?}",
                metadata.internals_visible_to_complete, metadata.internals_visible_to
            )
            .unwrap();
        }
        writeln!(rendered, "gaps:").unwrap();
        for gap in selection.gaps().unwrap() {
            writeln!(rendered, "  {} {} {}", gap.code, gap.path, gap.evidence).unwrap();
        }
        let expected = fixture_root.join("expected.txt");
        if std::env::var_os("BIFROST_BLESS").is_some() {
            fs::write(&expected, &rendered).unwrap();
        }
        assert_eq!(fs::read_to_string(expected).unwrap(), rendered);
    }

    #[test]
    fn sibling_projects_scope_global_using_sources() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
            ("B/B.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("B/App.cs", "namespace B; class App {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        // Edges stay inside the declaring project, but several projects'
        // default globs may compile sources the listing omits.
        assert!(!complete, "several projects are never a proven inventory");
        assert!(dependencies[&file(&project, "A/App.cs")].contains(&global));
        assert!(!dependencies.contains_key(&file(&project, "B/App.cs")));
    }

    #[test]
    fn explicit_linked_source_joins_the_declaring_compilation() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Shared/Linked.cs\"><Link>Linked.cs</Link></Compile></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("Shared/Linked.cs", "namespace Shared; class Linked {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(complete);
        assert!(dependencies[&file(&project, "Shared/Linked.cs")].contains(&global));
    }

    #[test]
    fn source_set_without_csproj_is_one_loose_compilation() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            ("GlobalUsings.cs", "global using Demo;"),
            ("App.cs", "namespace Demo; class App {}"),
        ]);
        let global = file(&project, "GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(complete);
        assert!(dependencies[&file(&project, "App.cs")].contains(&global));
    }

    #[test]
    fn unresolved_msbuild_item_is_incomplete_without_workspace_fallback() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"$(SharedRoot)/Linked.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
            ("Loose/Other.cs", "namespace Loose; class Other {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(!complete);
        assert!(dependencies.is_empty(), "{dependencies:?}");
        assert_eq!(
            analyzer.compilation_visibility(
                &file(&project, "A/App.cs"),
                &file(&project, "Loose/Other.cs")
            ),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    #[test]
    fn one_physical_source_in_two_compilations_is_reported_ambiguous() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            (
                "A/Nested/Nested.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
            ),
            ("A/Nested/Shared.cs", "namespace Shared; class Value {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let shared = file(&project, "A/Nested/Shared.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(!complete);
        assert!(!dependencies.contains_key(&shared));
        assert_eq!(
            analyzer.compilation_visibility(&shared, &global),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    #[test]
    #[hardwon(
        "#6296: a global-namespace type in an unreferenced project shadowed an imported type"
    )]
    fn project_references_decide_cross_compilation_visibility() {
        let sdk = "<Project Sdk=\"Microsoft.NET.Sdk\" />";
        let (_root, project, _analyzed, analyzer) = analyzed(&[
            (
                "App/App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup></Project>",
            ),
            ("App/Program.cs", "class Program {}"),
            ("App/Shadow.cs", "class Shadow {}"),
            (
                "Lib/Lib.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"..\\Core\\Core.csproj\"><Private>false</Private></ProjectReference></ItemGroup></Project>",
            ),
            ("Lib/Lib.cs", "class Lib {}"),
            ("Core/Core.csproj", sdk),
            ("Core/Core.cs", "class Core {}"),
            ("Core/bin/Generated.cs", "class Generated {}"),
            ("Tests/Tests.csproj", sdk),
            ("Tests/Fake.cs", "class Fake {}"),
            (
                "Aliased/Aliased.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../Core/Core.csproj\" Aliases=\"core\" /></ItemGroup></Project>",
            ),
            ("Aliased/Use.cs", "class Use {}"),
            (
                "Dangling/Dangling.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../Missing/Missing.csproj\" /></ItemGroup></Project>",
            ),
            ("Dangling/Use.cs", "class Use {}"),
            ("Loose.cs", "class Loose {}"),
        ]);
        let visibility = |from: &str, to: &str| {
            analyzer
                .compilation_visibility(&file(&project, from), &file(&project, to))
                .expect("membership reads succeed")
        };
        use CSharpCompilationVisibility::{NotVisible, Unresolved, Visible};

        assert_eq!(visibility("App/Program.cs", "App/Shadow.cs"), Visible);
        assert_eq!(visibility("App/Program.cs", "Lib/Lib.cs"), Visible);
        assert_eq!(
            visibility("App/Program.cs", "Core/Core.cs"),
            Visible,
            "SDK references flow transitively"
        );
        assert_eq!(visibility("Core/Core.cs", "App/Program.cs"), NotVisible);
        assert_eq!(visibility("App/Program.cs", "Tests/Fake.cs"), NotVisible);
        assert_eq!(
            visibility("App/Program.cs", "Core/bin/Generated.cs"),
            Unresolved,
            "build output is outside the default glob, so it belongs to no compilation"
        );
        assert_eq!(
            visibility("Aliased/Use.cs", "Core/Core.cs"),
            Unresolved,
            "an aliased reference does not merge into the global namespace"
        );
        assert_eq!(visibility("Aliased/Use.cs", "Tests/Fake.cs"), Unresolved);
        assert_eq!(visibility("Dangling/Use.cs", "Tests/Fake.cs"), Unresolved);
        assert_eq!(visibility("Dangling/Use.cs", "Dangling/Use.cs"), Visible);
        assert_eq!(visibility("Loose.cs", "App/Program.cs"), Unresolved);
    }

    #[test]
    #[hardwon(
        "#6296: ProjectReference metadata, Target bodies and disabled transitive flow published a visible edge"
    )]
    fn unproven_reference_shapes_never_prove_visibility() {
        let sdk = "<Project Sdk=\"Microsoft.NET.Sdk\" />";
        let app = |items: &str| format!("<Project Sdk=\"Microsoft.NET.Sdk\">{items}</Project>");
        for (project, evidence) in [
            (
                app(
                    "<ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\"><ReferenceOutputAssembly>false</ReferenceOutputAssembly></ProjectReference></ItemGroup>",
                ),
                "child ReferenceOutputAssembly",
            ),
            (
                app(
                    "<ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\"><Aliases>lib</Aliases></ProjectReference></ItemGroup>",
                ),
                "child Aliases",
            ),
            (
                app(
                    "<Target Name=\"NeverCalled\"><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup></Target>",
                ),
                "item inside a Target",
            ),
            (
                app(
                    "<Choose><When Condition=\"'$(X)' == 'y'\" /><Otherwise><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup></Otherwise></Choose>",
                ),
                "item inside an Otherwise branch",
            ),
        ] {
            let (_root, files, _analyzed, analyzer) = analyzed(&[
                ("App/App.csproj", &project),
                ("App/Program.cs", "class Program {}"),
                ("Lib/Lib.csproj", sdk),
                ("Lib/Lib.cs", "class Lib {}"),
            ]);
            assert_eq!(
                analyzer.compilation_visibility(
                    &file(&files, "App/Program.cs"),
                    &file(&files, "Lib/Lib.cs")
                ),
                Some(CSharpCompilationVisibility::Unresolved),
                "{evidence}"
            );
        }

        // Disabled transitive flow keeps direct references and unproves the
        // references' references.
        let (_root, files, _analyzed, analyzer) = analyzed(&[
            (
                "App/App.csproj",
                &app(
                    "<PropertyGroup><DisableTransitiveProjectReferences>true</DisableTransitiveProjectReferences></PropertyGroup><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup>",
                ),
            ),
            ("App/Program.cs", "class Program {}"),
            (
                "Lib/Lib.csproj",
                &app("<ItemGroup><ProjectReference Include=\"../Core/Core.csproj\" /></ItemGroup>"),
            ),
            ("Lib/Lib.cs", "class Lib {}"),
            ("Core/Core.csproj", sdk),
            ("Core/Core.cs", "class Core {}"),
        ]);
        let program = file(&files, "App/Program.cs");
        assert_eq!(
            analyzer.compilation_visibility(&program, &file(&files, "Lib/Lib.cs")),
            Some(CSharpCompilationVisibility::Visible)
        );
        assert_eq!(
            analyzer.compilation_visibility(&program, &file(&files, "Core/Core.cs")),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    #[test]
    fn compile_items_inside_a_target_leave_membership_unproven() {
        // Old producers applied the Target's include unconditionally and
        // proved the linked source a member of App.
        let (_root, files, _analyzed, analyzer) = analyzed(&[
            (
                "App/App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><Target Name=\"NeverCalled\"><ItemGroup><Compile Include=\"../Shared/Linked.cs\" /></ItemGroup></Target></Project>",
            ),
            ("App/Program.cs", "class Program {}"),
            ("Shared/Linked.cs", "class Linked {}"),
        ]);
        assert_eq!(
            analyzer.compilation_visibility(
                &file(&files, "App/Program.cs"),
                &file(&files, "Shared/Linked.cs")
            ),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    #[test]
    #[hardwon("#6296: an ignored Directory.Build.props never entered the compilation inputs")]
    fn ignored_directory_build_files_are_probed_inputs() {
        let (root, files, analyzer) = analyzed_ignoring(
            &[
                (
                    "Directory.Build.props",
                    "<Project><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>",
                ),
                ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
                ("A/App.cs", "class App {}"),
                ("A/Other.cs", "class Other {}"),
            ],
            &["Directory.Build.props"],
        );
        assert!(
            !files
                .all_files()
                .expect("listing")
                .iter()
                .any(|listed| listed.rel_path() == Path::new("Directory.Build.props")),
            "the fixture's Directory.Build.props is ignored by the listing"
        );
        let app = file(&files.delegate, "A/App.cs");
        let other = file(&files.delegate, "A/Other.cs");
        assert_eq!(
            analyzer.compilation_visibility(&app, &other),
            Some(CSharpCompilationVisibility::Unresolved)
        );

        fs::remove_file(root.path().join("Directory.Build.props")).expect("remove props");
        assert!(
            analyzer.inner.workspace_configuration_changed(),
            "removing the ignored input changes the configuration"
        );
        let props = ProjectFile::new(root.path().to_path_buf(), "Directory.Build.props");
        let updated = analyzer.update(&BTreeSet::from([props]));
        assert_eq!(
            updated.compilation_visibility(&app, &other),
            Some(CSharpCompilationVisibility::Visible)
        );
    }

    #[test]
    #[hardwon(
        "#6296: with no selected global using, global-using dependencies claimed completeness without the membership proof"
    )]
    fn global_dependency_completeness_needs_the_membership_proof_without_known_globals() {
        use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
        // What the file-dependency provider reports for `files` when no
        // selected source declares a global using.
        let provider_complete = |analyzer: &CSharpAnalyzer, files: &[ProjectFile]| {
            let dependencies = analyzer
                .additional_direct_file_dependencies(files, &CancellationToken::new())
                .expect("not cancelled");
            assert!(dependencies.dependencies.is_empty(), "{dependencies:?}");
            dependencies.complete
        };
        let sdk = "<Project Sdk=\"Microsoft.NET.Sdk\" />";

        let (_root, _project, analyzed_files, analyzer) =
            analyzed(&[("A/A.csproj", sdk), ("A/App.cs", "class App {}")]);
        assert!(
            provider_complete(&analyzer, &analyzed_files),
            "one project with proven membership"
        );

        let (_root, _project, analyzed_files, analyzer) = analyzed(&[
            ("A/A.csproj", sdk),
            ("A/App.cs", "class App {}"),
            ("B/B.csproj", sdk),
            ("B/Other.cs", "class Other {}"),
        ]);
        assert!(
            !provider_complete(&analyzer, &analyzed_files),
            "several projects' default globs are not a proven inventory"
        );

        // An ignored source the SDK default glob still compiles: no recorded
        // input shows it, so the selection cannot certify completeness.
        let (_root, project, analyzer) = analyzed_ignoring(
            &[
                ("A/A.csproj", sdk),
                ("A/Use.cs", "namespace A; class Use { Service service; }"),
                ("A/Types.cs", "namespace Shared; public class Service {}"),
                ("A/Generated/Globals.cs", "global using Shared;"),
                ("B/B.csproj", sdk),
                ("B/Other.cs", "class Other {}"),
            ],
            &["A/Generated/Globals.cs"],
        );
        let listed = project
            .analyzable_files(Language::CSharp)
            .expect("C# files")
            .into_iter()
            .collect::<Vec<_>>();
        assert!(
            !provider_complete(&analyzer, &listed),
            "an ignored default-glob source may hold global usings"
        );

        let (_root, project, analyzer) = analyzed_ignoring(
            &[
                (
                    "A/A.csproj",
                    "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Generated/Globals.cs\" /></ItemGroup></Project>",
                ),
                ("A/App.cs", "class App {}"),
                ("Generated/Globals.cs", "global using Shared;"),
            ],
            &["Generated/Globals.cs"],
        );
        let listed = project
            .analyzable_files(Language::CSharp)
            .expect("C# files")
            .into_iter()
            .collect::<Vec<_>>();
        assert!(
            !provider_complete(&analyzer, &listed),
            "an unselected included source may hold global usings"
        );

        let (_root, _project, analyzed_files, analyzer) = analyzed(&[
            (
                "Directory.Build.props",
                "<Project><Import Project=\"$(RepoRoot)eng/common.props\" /></Project>",
            ),
            ("A/A.csproj", sdk),
            ("A/App.cs", "class App {}"),
        ]);
        assert!(
            !provider_complete(&analyzer, &analyzed_files),
            "a recorded gap stays a gap"
        );

        let (root, project, analyzed_files, analyzer) =
            analyzed(&[("A/A.csproj", sdk), ("A/App.cs", "class App {}")]);
        let overlay = Arc::new(OverlayProject::new(project as Arc<dyn Project>));
        assert!(overlay.set(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Elsewhere.cs\" /></ItemGroup></Project>".to_owned(),
        ));
        assert!(
            !provider_complete(&analyzer.clone_with_project(overlay), &analyzed_files),
            "rows cannot describe an overlaid project file"
        );
    }

    #[test]
    fn directory_build_chains_and_tree_includes_are_evaluated() {
        let sdk = "<Project Sdk=\"Microsoft.NET.Sdk\" />";
        let (_root, project, _analyzed, analyzer) = analyzed(&[
            (
                "Directory.Build.props",
                "<Project><PropertyGroup><LangVersion>13</LangVersion></PropertyGroup><ItemGroup Condition=\"'$(Configuration)' == 'Release'\"><SourceRoot Include=\"$(MSBuildThisFileDirectory)/\" /></ItemGroup></Project>",
            ),
            (
                "tests/Directory.Build.props",
                "<Project><PropertyGroup><AssemblyName>Tests</AssemblyName></PropertyGroup><Import Project=\"$(MSBuildThisFileDirectory)..\\Directory.Build.props\" /><ItemGroup><ProjectReference Include=\"../../Lib/Lib.csproj\" /></ItemGroup></Project>",
            ),
            ("Lib/Lib.csproj", sdk),
            ("Lib/Lib.cs", "class Lib {}"),
            ("Lib/obj/Generated.cs", "class Generated {}"),
            ("tests/T/T.csproj", sdk),
            ("tests/T/Test.cs", "class Test {}"),
            (
                "Strong/Strong.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"..\\Lib\\**\\*.cs\" Exclude=\"..\\Lib\\obj\\**\\*.cs\" /></ItemGroup></Project>",
            ),
            ("Strong/S.cs", "class S {}"),
        ]);
        let visibility = |from: &str, to: &str| {
            analyzer
                .compilation_visibility(&file(&project, from), &file(&project, to))
                .expect("membership reads succeed")
        };
        use CSharpCompilationVisibility::{NotVisible, Unresolved, Visible};
        assert_eq!(
            visibility("tests/T/Test.cs", "Lib/Lib.cs"),
            Visible,
            "a ProjectReference written in an imported Directory.Build.props applies to the project"
        );
        assert_eq!(
            visibility("Strong/S.cs", "Lib/Lib.cs"),
            Visible,
            "a tree include compiles the other directory's sources"
        );
        assert_eq!(
            visibility("Lib/Lib.cs", "Strong/S.cs"),
            Unresolved,
            "Lib.cs is compiled by Lib, which cannot see Strong, and by Strong, which can"
        );
        assert_eq!(visibility("Lib/Lib.cs", "tests/T/Test.cs"), NotVisible);
        assert_eq!(
            visibility("Strong/S.cs", "Lib/obj/Generated.cs"),
            Unresolved,
            "the tree's Exclude and the default glob both leave build output out"
        );
    }

    #[test]
    fn unfollowable_directory_build_inputs_leave_membership_unproven() {
        let sdk = "<Project Sdk=\"Microsoft.NET.Sdk\" />";
        for (props, evidence) in [
            (
                "<Project><Import Project=\"$(RepoRoot)eng/common.props\" /></Project>",
                "a dynamic import",
            ),
            (
                "<Project><Import Project=\"missing.props\" /></Project>",
                "an import outside the inputs",
            ),
            (
                "<Project><PropertyGroup><EnableDefaultCompileItems Condition=\"'$(X)' == 'y'\">false</EnableDefaultCompileItems></PropertyGroup></Project>",
                "a conditioned default-item property",
            ),
            (
                "<Project><PropertyGroup><ImportDirectoryBuildTargets>false</ImportDirectoryBuildTargets></PropertyGroup></Project>",
                "a moved import scope",
            ),
            (
                "<Project><ItemGroup><Compile Include=\"Gen/*.g.cs\" /></ItemGroup></Project>",
                "a non-tree glob",
            ),
        ] {
            let (_root, project, _analyzed, analyzer) = analyzed(&[
                ("Directory.Build.props", props),
                ("A/A.csproj", sdk),
                ("A/App.cs", "class App {}"),
                ("A/Other.cs", "class Other {}"),
            ]);
            assert_eq!(
                analyzer.compilation_visibility(
                    &file(&project, "A/App.cs"),
                    &file(&project, "A/Other.cs")
                ),
                Some(CSharpCompilationVisibility::Unresolved),
                "{evidence}"
            );
        }
    }

    #[test]
    fn project_and_source_updates_republish_membership() {
        let (root, project, _analyzed, analyzer) = analyzed(&[
            ("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("App/Program.cs", "class Program {}"),
            ("Lib/Lib.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("Lib/Lib.cs", "class Lib {}"),
        ]);
        let program = file(&project, "App/Program.cs");
        let lib = file(&project, "Lib/Lib.cs");
        assert_eq!(
            analyzer.compilation_visibility(&program, &lib),
            Some(CSharpCompilationVisibility::NotVisible)
        );

        fs::write(
            root.path().join("App/App.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup></Project>",
        )
        .expect("edit project file");
        let referenced = analyzer.update(&BTreeSet::from([file(&project, "App/App.csproj")]));
        assert_eq!(
            referenced.compilation_visibility(&program, &lib),
            Some(CSharpCompilationVisibility::Visible)
        );

        fs::write(root.path().join("Lib/Added.cs"), "class Added {}").expect("add source");
        let added = file(&project, "Lib/Added.cs");
        let with_source = referenced.update(&BTreeSet::from([added.clone()]));
        assert_eq!(
            with_source.compilation_visibility(&program, &added),
            Some(CSharpCompilationVisibility::Visible),
            "a new source joins its project's default glob without new rules"
        );
        assert_eq!(
            referenced.compilation_visibility(&program, &added),
            Some(CSharpCompilationVisibility::Unresolved),
            "the earlier revision does not select the new source"
        );
    }

    #[test]
    fn configuration_overlay_leaves_membership_unproven() {
        let (root, project, _analyzed, analyzer) = analyzed(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/App.cs", "class App {}"),
            ("A/Other.cs", "class Other {}"),
        ]);
        let app = file(&project, "A/App.cs");
        let other = file(&project, "A/Other.cs");
        assert_eq!(
            analyzer.compilation_visibility(&app, &other),
            Some(CSharpCompilationVisibility::Visible)
        );
        let overlay = Arc::new(OverlayProject::new(project as Arc<dyn Project>));
        assert!(overlay.set(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Remove=\"Other.cs\" /></ItemGroup></Project>".to_owned(),
        ));
        let cloned = analyzer.clone_with_project(overlay);
        assert_eq!(
            cloned.compilation_visibility(&app, &other),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    fn two_project_fixture() -> (tempfile::TempDir, Arc<TestProject>, CSharpAnalyzer) {
        let (root, project, _analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/App.cs", "namespace A; class App {}"),
            ("B/B.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("B/App.cs", "namespace B; class App {}"),
        ]);
        let project = Arc::new(project);
        let analyzer = CSharpAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>);
        (root, project, analyzer)
    }

    #[test]
    #[hardwon(
        "#5682: a partial C# compilation graph re-listed the workspace on every snapshot identity check"
    )]
    fn partial_compilation_graph_keeps_one_snapshot_identity_without_retaining_the_graph() {
        let (_root, project, analyzer) = two_project_fixture();
        let identity = analyzer
            .workspace_content_identities()
            .expect("known config identity");
        let listings = project.workspace_file_listing_count();

        for _ in 0..5 {
            assert_eq!(
                analyzer.workspace_content_identities().as_ref(),
                Some(&identity)
            );
        }
        assert_eq!(project.workspace_file_listing_count(), listings);
        assert!(analyzer.memo_caches.compilation_config_digest.is_ready());
    }

    /// Delegates to a disk project but leaves `ignored` out of its listings,
    /// as ignore rules do; the files stay readable by path.
    struct IgnoringProject {
        delegate: TestProject,
        ignored: Vec<PathBuf>,
    }

    impl Project for IgnoringProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
            let mut files = self.delegate.all_files()?;
            files.retain(|file| !self.ignored.iter().any(|path| file.rel_path() == path));
            Ok(files)
        }

        fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
            let mut files = self.delegate.analyzable_files(language)?;
            files.retain(|file| !self.ignored.iter().any(|path| file.rel_path() == path));
            Ok(files)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }
    }

    /// The analyzer of `files` over a project whose listings omit `ignored`.
    fn analyzed_ignoring(
        files: &[(&str, &str)],
        ignored: &[&str],
    ) -> (tempfile::TempDir, Arc<IgnoringProject>, CSharpAnalyzer) {
        let (root, delegate, _analyzed) = fixture(files);
        let project = Arc::new(IgnoringProject {
            delegate,
            ignored: ignored.iter().map(PathBuf::from).collect(),
        });
        let analyzer = CSharpAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>);
        (root, project, analyzer)
    }

    /// Delegates to a disk project, but its listing fails while `fail_listing`
    /// is set: the transient failure of a workspace walk.
    struct FlakyListingProject {
        delegate: TestProject,
        fail_listing: AtomicBool,
    }

    impl Project for FlakyListingProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
            if self.fail_listing.load(Ordering::SeqCst) {
                return Err(io::Error::other("listing interrupted"));
            }
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn workspace_file_listing_count(&self) -> usize {
            self.delegate.workspace_file_listing_count()
        }
    }

    #[test]
    #[hardwon(
        "#5682: an unknown C# config identity must not be memoized for the rest of its generation"
    )]
    fn unknown_config_identity_is_retried_in_the_same_generation() {
        let (root, delegate, _analyzed) = fixture(&[
            ("A/A.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("A/App.cs", "namespace A; class App {}"),
            ("B/B.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("B/App.cs", "namespace B; class App {}"),
        ]);
        let project = Arc::new(FlakyListingProject {
            delegate,
            fail_listing: AtomicBool::new(false),
        });
        let analyzer = CSharpAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>);

        project.fail_listing.store(true, Ordering::SeqCst);
        assert_eq!(analyzer.workspace_content_identities(), None);
        project.fail_listing.store(false, Ordering::SeqCst);

        let csproj = root.path().join("B/B.csproj");
        let original = fs::read_to_string(&csproj).expect("read project file");
        let oversized = format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><!--{}--></Project>",
            " ".repeat(MAX_PROJECT_BYTES)
        );
        fs::write(&csproj, oversized).expect("write oversized project file");
        assert_eq!(analyzer.workspace_content_identities(), None);

        fs::write(&csproj, original).expect("restore project file");
        let identity = analyzer
            .workspace_content_identities()
            .expect("recovered config identity");
        assert_eq!(
            analyzer.workspace_content_identities().as_ref(),
            Some(&identity)
        );
    }

    #[test]
    fn config_and_source_edits_rotate_the_snapshot_identity_on_update() {
        let (root, project, analyzer) = two_project_fixture();
        let initial = analyzer
            .workspace_content_identities()
            .expect("initial identity");

        fs::write(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Nullable>enable</Nullable></PropertyGroup></Project>",
        )
        .expect("edit project file");
        // A generation answers from the inputs it was built from.
        assert_eq!(
            analyzer.workspace_content_identities().as_ref(),
            Some(&initial)
        );
        let config_updated = analyzer.update(&BTreeSet::from([file(&project, "A/A.csproj")]));
        let after_config = config_updated
            .workspace_content_identities()
            .expect("updated config identity");
        assert_ne!(after_config, initial);

        fs::write(
            root.path().join("B/App.cs"),
            "namespace B; class App { void Run() {} }",
        )
        .expect("edit source file");
        let source_updated = config_updated.update(&BTreeSet::from([file(&project, "B/App.cs")]));
        let after_source = source_updated
            .workspace_content_identities()
            .expect("updated source identity");
        assert_ne!(after_source, after_config);
        assert_eq!(
            config_updated.compilation_config_digest(),
            source_updated.compilation_config_digest()
        );
    }

    #[test]
    fn disabled_default_items_do_not_claim_directory_sources() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultItems>false</EnableDefaultItems></PropertyGroup><ItemGroup><Compile Include=\"GlobalUsings.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/Unlisted.cs", "namespace A; class Unlisted {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let unlisted = file(&project, "A/Unlisted.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(!complete, "an uncompiled source has no proven compilation");
        assert!(!dependencies.contains_key(&unlisted));
        assert_eq!(
            analyzer.compilation_visibility(&global, &unlisted),
            Some(CSharpCompilationVisibility::Unresolved)
        );
    }

    #[test]
    fn custom_default_excludes_are_reported_incomplete() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><DefaultItemExcludes>Generated/**/*.cs</DefaultItemExcludes></PropertyGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(!complete);
        assert!(dependencies.is_empty(), "{dependencies:?}");
    }

    #[test]
    fn literal_exclude_filters_only_its_include_item() {
        let (_root, project, analyzed, analyzer) = analyzed(&[
            (
                "A/A.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include=\"GlobalUsings.cs\" /><Compile Include=\"App.cs\" Exclude=\"GlobalUsings.cs\" /></ItemGroup></Project>",
            ),
            ("A/GlobalUsings.cs", "global using A.Shared;"),
            ("A/App.cs", "namespace A; class App {}"),
        ]);
        let global = file(&project, "A/GlobalUsings.cs");
        let (dependencies, complete) = global_dependencies(&analyzer, &analyzed, &global);

        assert!(complete);
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
            assert!(!parsed.sdk_project, "{source}");
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
            .compilation_config_digest()
            .expect("disk config identity");

        let overlay = Arc::new(OverlayProject::new(project));
        assert!(overlay.set(
            root.path().join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Nullable>enable</Nullable></PropertyGroup></Project>".to_owned(),
        ));
        let cloned = analyzer.clone_with_project(overlay);
        let after = cloned
            .compilation_config_digest()
            .expect("overlay config identity");

        assert_ne!(before, after);
    }

    /// Where the selected rules place `path`: compiled by some project,
    /// outside every compilation, or unproven.
    fn membership(analyzer: &CSharpAnalyzer, path: &str) -> &'static str {
        let selection = analyzer
            .selected_compilations()
            .expect("membership reads succeed")
            .expect("a selected membership");
        match selection
            .compilations_of(path)
            .expect("membership reads succeed")
        {
            None => "unproven",
            Some(compilations) if compilations.is_empty() => "outside",
            Some(_) => "member",
        }
    }

    fn facts_of(files: &[(&str, &str)]) -> CSharpCompilationFacts {
        let inputs = files
            .iter()
            .map(|(path, source)| CSharpConfigurationInput {
                rel_path: (*path).to_owned(),
                source: Some(source.as_bytes().to_vec()),
            })
            .collect::<Vec<_>>();
        compilation_facts(&inputs)
    }

    #[test]
    #[hardwon(
        "#6296: a Directory.Build.props Compile Remove applied after the SDK default Include"
    )]
    fn props_items_apply_before_the_sdk_default_items() {
        // Microsoft.Common.props imports Directory.Build.props before
        // Microsoft.NET.Sdk.props adds the default Compile glob; the
        // project body and Directory.Build.targets come after it.
        let (_root, _project, _analyzed, analyzer) = analyzed(&[
            (
                "Directory.Build.props",
                "<Project><ItemGroup><Compile Remove=\"Early.cs\" /></ItemGroup></Project>",
            ),
            (
                "App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Remove=\"Body.cs\" /></ItemGroup></Project>",
            ),
            (
                "Directory.Build.targets",
                "<Project><ItemGroup><Compile Remove=\"Late.cs\" /></ItemGroup></Project>",
            ),
            ("Early.cs", "class Early {}"),
            ("Body.cs", "class Body {}"),
            ("Late.cs", "class Late {}"),
        ]);
        assert_eq!(membership(&analyzer, "Early.cs"), "member");
        assert_eq!(membership(&analyzer, "Body.cs"), "outside");
        assert_eq!(membership(&analyzer, "Late.cs"), "outside");
    }

    #[test]
    #[hardwon(
        "#6296: the default glob dropped every bin/obj component and kept hidden directories and moved output roots"
    )]
    fn sdk_default_glob_excludes_its_output_roots_and_hidden_directories() {
        let (_root, _project, _analyzed, analyzer) = analyzed(&[
            (
                "Plain/Plain.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
            ),
            ("Plain/Use.cs", "class Use {}"),
            ("Plain/bin/B.cs", "class B {}"),
            ("Plain/obj/O.cs", "class O {}"),
            ("Plain/Sub/bin/Real.cs", "class Real {}"),
            ("Plain/Sub/obj/Kept.cs", "class Kept {}"),
            ("Plain/.hidden/Hidden.cs", "class Hidden {}"),
            ("Plain/Sub/.vs/Nested.cs", "class Nested {}"),
            (
                "Moved/Directory.Build.props",
                "<Project><PropertyGroup><BaseIntermediateOutputPath>generated</BaseIntermediateOutputPath></PropertyGroup></Project>",
            ),
            (
                "Moved/Moved.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><BaseOutputPath>artifacts/</BaseOutputPath></PropertyGroup></Project>",
            ),
            ("Moved/bin/B.cs", "class B {}"),
            ("Moved/obj/O.cs", "class O {}"),
            ("Moved/artifacts/G.cs", "class G {}"),
            ("Moved/generated/G.cs", "class G {}"),
        ]);
        for (path, expected) in [
            ("Plain/Use.cs", "member"),
            ("Plain/bin/B.cs", "outside"),
            ("Plain/obj/O.cs", "outside"),
            ("Plain/Sub/bin/Real.cs", "member"),
            ("Plain/Sub/obj/Kept.cs", "member"),
            ("Plain/.hidden/Hidden.cs", "outside"),
            ("Plain/Sub/.vs/Nested.cs", "outside"),
            ("Moved/bin/B.cs", "member"),
            ("Moved/obj/O.cs", "member"),
            ("Moved/artifacts/G.cs", "outside"),
            ("Moved/generated/G.cs", "outside"),
        ] {
            assert_eq!(membership(&analyzer, path), expected, "{path}");
        }
    }

    #[test]
    #[hardwon("#6296: SDK properties that change the default Compile set were ignored")]
    fn unevaluated_default_item_properties_leave_membership_unproven() {
        let project = |properties: &str| {
            format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{properties}</PropertyGroup></Project>"
            )
        };
        for properties in [
            "<DefaultItemExcludesInProjectFolder>Excluded/**</DefaultItemExcludesInProjectFolder>",
            "<DefaultExcludesInProjectFolder>Excluded/**</DefaultExcludesInProjectFolder>",
            "<DisableDefaultItemsInProjectFolder>true</DisableDefaultItemsInProjectFolder>",
            "<DefaultLanguageSourceExtension>.cs2</DefaultLanguageSourceExtension>",
            "<UsingNETSdkDefaults>false</UsingNETSdkDefaults>",
            "<OutputPath>out/</OutputPath>",
            "<PublishDir>out/</PublishDir>",
            "<UseArtifactsOutput>true</UseArtifactsOutput>",
            "<ArtifactsPath>out</ArtifactsPath>",
            "<BaseOutputPath>$(Root)out/</BaseOutputPath>",
            "<BaseIntermediateOutputPath>../../outside/</BaseIntermediateOutputPath>",
            "<CustomBeforeDirectoryBuildProps>x.props</CustomBeforeDirectoryBuildProps>",
            "<AlternateCommonProps>x.props</AlternateCommonProps>",
            "<BeforeMicrosoftNETSdkTargets>x.targets</BeforeMicrosoftNETSdkTargets>",
            "<LanguageTargets>x.targets</LanguageTargets>",
        ] {
            let facts = facts_of(&[("App/App.csproj", &project(properties))]);
            assert!(!facts.membership_complete, "{properties}: {facts:?}");
        }
        // The default excludes are expanded before Directory.Build.targets.
        let facts = facts_of(&[
            ("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            (
                "Directory.Build.targets",
                "<Project><PropertyGroup><BaseOutputPath>out/</BaseOutputPath></PropertyGroup></Project>",
            ),
        ]);
        assert!(!facts.membership_complete, "{facts:?}");
        // An SDK whose default items are not modeled.
        let facts = facts_of(&[(
            "App/App.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\" />",
        )]);
        assert!(!facts.membership_complete, "{facts:?}");
    }

    #[test]
    #[hardwon(
        "#6296: ProjectReference Remove, Update and item definitions left the earlier edge proven"
    )]
    fn project_reference_mutations_withhold_their_edges() {
        let app = |items: &str| format!("<Project Sdk=\"Microsoft.NET.Sdk\">{items}</Project>");
        let include = "<ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup>";
        for (project, targets, expected) in [
            (app(include), None, CSharpCompilationVisibility::Visible),
            (
                app("<ItemGroup><projectreference Include=\"../Lib/Lib.csproj\" /></ItemGroup>"),
                None,
                CSharpCompilationVisibility::Visible,
            ),
            (
                app(&format!(
                    "{include}<ItemGroup><ProjectReference Remove=\"../Lib/Lib.csproj\" /></ItemGroup>"
                )),
                None,
                CSharpCompilationVisibility::Unresolved,
            ),
            (
                app(&format!(
                    "{include}<ItemGroup><ProjectReference Update=\"../Lib/Lib.csproj\" ReferenceOutputAssembly=\"false\" /></ItemGroup>"
                )),
                None,
                CSharpCompilationVisibility::Unresolved,
            ),
            (
                app(&format!(
                    "<ItemDefinitionGroup><ProjectReference><ReferenceOutputAssembly>false</ReferenceOutputAssembly></ProjectReference></ItemDefinitionGroup>{include}"
                )),
                None,
                CSharpCompilationVisibility::Unresolved,
            ),
            (
                app(include),
                Some(
                    "<Project><ItemGroup><ProjectReference Update=\"@(ProjectReference)\" ReferenceOutputAssembly=\"false\" /></ItemGroup></Project>",
                ),
                CSharpCompilationVisibility::Unresolved,
            ),
            (
                app(
                    "<ItemGroup><projectreference Include=\"../Lib/Lib.csproj\"><referenceoutputassembly>false</referenceoutputassembly></projectreference></ItemGroup>",
                ),
                None,
                CSharpCompilationVisibility::Unresolved,
            ),
        ] {
            let mut files = vec![
                ("App/App.csproj", project.as_str()),
                ("App/Program.cs", "class Program {}"),
                ("Lib/Lib.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
                ("Lib/Lib.cs", "class Lib {}"),
            ];
            if let Some(targets) = targets {
                files.push(("Directory.Build.targets", targets));
            }
            let (_root, project_files, _analyzed, analyzer) = analyzed(&files);
            assert_eq!(
                analyzer.compilation_visibility(
                    &file(&project_files, "App/Program.cs"),
                    &file(&project_files, "Lib/Lib.cs")
                ),
                Some(expected),
                "{project} {targets:?}"
            );
        }
    }

    #[test]
    #[hardwon("#6296: an empty EnableDefaultCompileItems kept the earlier false")]
    fn an_empty_property_assignment_restores_the_sdk_default() {
        let disabled = "<Project><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>";
        let project = |properties: &str| {
            format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{properties}</PropertyGroup></Project>"
            )
        };
        for (props, body, targets, expected) in [
            (
                Some(disabled),
                "<EnableDefaultCompileItems />",
                None,
                "member",
            ),
            (
                Some(disabled),
                "<EnableDefaultCompileItems></EnableDefaultCompileItems>",
                None,
                "member",
            ),
            (Some(disabled), "", None, "outside"),
            // The SDK fills an empty value in before Directory.Build.targets;
            // an empty value written there stays empty, which is not true.
            (
                None,
                "",
                Some(
                    "<Project><PropertyGroup><EnableDefaultCompileItems /></PropertyGroup></Project>",
                ),
                "outside",
            ),
        ] {
            let body = project(body);
            let mut files = vec![("App.csproj", body.as_str()), ("X.cs", "class X {}")];
            if let Some(props) = props {
                files.push(("Directory.Build.props", props));
            }
            if let Some(targets) = targets {
                files.push(("Directory.Build.targets", targets));
            }
            let (_root, _project, _analyzed, analyzer) = analyzed(&files);
            assert_eq!(
                membership(&analyzer, "X.cs"),
                expected,
                "{props:?} {body} {targets:?}"
            );
        }
        let (_root, _project, _analyzed, analyzer) = analyzed(&[
            ("App.csproj", &project("<BaseOutputPath />")),
            ("bin/B.cs", "class B {}"),
        ]);
        assert_eq!(membership(&analyzer, "bin/B.cs"), "outside");
    }

    #[test]
    #[hardwon("#6296: MSBuild property and item names were matched case-sensitively")]
    fn msbuild_property_and_item_names_ignore_case() {
        let (_root, _project, _analyzed, analyzer) = analyzed(&[
            (
                "App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><enabledefaultcompileitems>false</enabledefaultcompileitems></PropertyGroup><ItemGroup><COMPILE Include=\"Listed.cs\" /></ItemGroup></Project>",
            ),
            ("Listed.cs", "class Listed {}"),
            ("Unlisted.cs", "class Unlisted {}"),
        ]);
        assert_eq!(membership(&analyzer, "Listed.cs"), "member");
        assert_eq!(membership(&analyzer, "Unlisted.cs"), "outside");

        let facts = facts_of(&[(
            "App.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><defaultitemexcludes>X/**</defaultitemexcludes></PropertyGroup></Project>",
        )]);
        assert!(!facts.membership_complete, "{facts:?}");
    }
    #[test]
    fn review_r5_unsupported_property_gaps_reach_membership_reader() {
        for property in [
            "<DefaultItemExcludesInProjectFolder>Excluded/**</DefaultItemExcludesInProjectFolder>",
            "<DefaultExcludesInProjectFolder>Excluded/**</DefaultExcludesInProjectFolder>",
            "<PublishDir>Excluded/</PublishDir>",
            "<DefaultLanguageSourceExtension>.cs2</DefaultLanguageSourceExtension>",
            "<BaseOutputPath>$(Root)out/</BaseOutputPath>",
            "<BaseIntermediateOutputPath>../../outside/</BaseIntermediateOutputPath>",
        ] {
            let xml = format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{property}</PropertyGroup></Project>"
            );
            let (_root, _, _, analyzer) =
                analyzed(&[("App.csproj", &xml), ("Excluded/X.cs", "class X {}")]);
            assert_eq!(
                membership(&analyzer, "Excluded/X.cs"),
                "unproven",
                "{property}"
            );
        }
    }
    #[test]
    #[hardwon("#6296: an XML character reference in a property value was dropped")]
    fn review_r5_xml_character_references_in_output_root() {
        let (_root, _, _, analyzer) = analyzed(&[
            (
                "App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><BaseOutputPath>o&#117;t/</BaseOutputPath></PropertyGroup></Project>",
            ),
            ("out/G.cs", "class G {}"),
            ("ot/H.cs", "class H {}"),
        ]);
        assert_eq!(
            membership(&analyzer, "out/G.cs"),
            "outside",
            "XML character reference must decode to out/"
        );
        assert_eq!(membership(&analyzer, "ot/H.cs"), "member");
    }
    #[test]
    #[hardwon("#6296: a non-SDK project received the implicit Directory.Build imports")]
    fn review_r5_non_sdk_has_no_implicit_directory_build_import() {
        let (_root, _, _, analyzer) = analyzed(&[
            (
                "App.csproj",
                "<Project><ItemGroup><Compile Include=\"Listed.cs\" /></ItemGroup></Project>",
            ),
            (
                "Directory.Build.targets",
                "<Project><ItemGroup><Compile Include=\"Extra.cs\" /></ItemGroup></Project>",
            ),
            ("Listed.cs", "class Listed {}"),
            ("Extra.cs", "class Extra {}"),
        ]);
        assert_eq!(membership(&analyzer, "Listed.cs"), "member");
        assert_eq!(
            membership(&analyzer, "Extra.cs"),
            "outside",
            "No Sdk or explicit common targets import"
        );
    }

    #[test]
    fn review_r5_nested_imports_restore_the_import_base_and_targets_order() {
        let (_root, _, _, analyzer) = analyzed(&[
            (
                "App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"Z.cs\"/></ItemGroup></Project>",
            ),
            (
                "Directory.Build.props",
                "<Project><Import Project=\"config/outer.props\"/><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>",
            ),
            (
                "config/outer.props",
                "<Project><Import Project=\"inner/one.props\"/><Import Project=\"two.props\"/></Project>",
            ),
            (
                "config/inner/one.props",
                "<Project><ItemGroup><Compile Include=\"X.cs\"/></ItemGroup></Project>",
            ),
            (
                "config/two.props",
                "<Project><ItemGroup><Compile Include=\"Y.cs\"/></ItemGroup></Project>",
            ),
            (
                "Directory.Build.targets",
                "<Project><Import Project=\"config/late.targets\"/><ItemGroup><Compile Include=\"Extra.cs\"/></ItemGroup></Project>",
            ),
            (
                "config/late.targets",
                "<Project><ItemGroup><Compile Remove=\"X.cs\"/></ItemGroup></Project>",
            ),
            ("X.cs", "class X {}"),
            ("Y.cs", "class Y {}"),
            ("Z.cs", "class Z {}"),
            ("Extra.cs", "class Extra {}"),
        ]);
        for (path, expected) in [
            ("X.cs", "outside"),
            ("Y.cs", "member"),
            ("Z.cs", "member"),
            ("Extra.cs", "member"),
        ] {
            assert_eq!(membership(&analyzer, path), expected, "{path}");
        }
    }
    #[test]
    fn review_r5_unmodeled_import_forms_are_unproven_in_reader() {
        for import in [
            "<Import Project=\"x.props\" Condition=\"'true' == 'true'\"/>",
            "<Import Project=\"*.props\"/>",
            "<Import Project=\"$([MSBuild]::GetPathOfFileAbove('x.props'))\"/>",
        ] {
            let props = format!("<Project>{import}</Project>");
            let (_root, _, _, analyzer) = analyzed(&[
                ("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"/>"),
                ("Directory.Build.props", &props),
                ("x.props", "<Project/>"),
                ("X.cs", "class X {}"),
            ]);
            assert_eq!(membership(&analyzer, "X.cs"), "unproven", "{import}");
        }
    }

    #[test]
    #[hardwon("#6296: an XML character reference in a property value was dropped")]
    fn xml_references_in_property_values_decode_or_leave_membership_unproven() {
        let project = |root: &str| {
            format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><BaseOutputPath>{root}</BaseOutputPath></PropertyGroup></Project>"
            )
        };
        for (root, excluded, expected) in [
            ("o&#x75;t/", "out/G.cs", "outside"),
            ("a&amp;b/", "a&b/G.cs", "outside"),
            ("o&unknown;t/", "out/G.cs", "unproven"),
            ("o&#xD800;t/", "out/G.cs", "unproven"),
        ] {
            let (_root, _, _, analyzer) =
                analyzed(&[("App.csproj", &project(root)), (excluded, "class G {}")]);
            assert_eq!(membership(&analyzer, excluded), expected, "{root}");
        }
    }

    #[test]
    fn non_sdk_projects_reach_directory_build_files_only_through_their_imports() {
        // A legacy project imports Microsoft.Common.props/.targets (which
        // import the Directory.Build files) through dynamic paths: a gap.
        let (_root, _, _, analyzer) = analyzed(&[
            (
                "App.csproj",
                "<Project><Import Project=\"$(MSBuildToolsPath)\\Microsoft.CSharp.targets\" /><ItemGroup><Compile Include=\"Listed.cs\" /></ItemGroup></Project>",
            ),
            (
                "Directory.Build.targets",
                "<Project><ItemGroup><Compile Include=\"Extra.cs\" /></ItemGroup></Project>",
            ),
            ("Listed.cs", "class Listed {}"),
            ("Extra.cs", "class Extra {}"),
        ]);
        assert_eq!(membership(&analyzer, "Extra.cs"), "unproven");
        // An SDK project does receive them.
        let (_root, _, _, analyzer) = analyzed(&[
            ("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            (
                "Directory.Build.targets",
                "<Project><ItemGroup><Compile Remove=\"Extra.cs\" /></ItemGroup></Project>",
            ),
            ("Listed.cs", "class Listed {}"),
            ("Extra.cs", "class Extra {}"),
        ]);
        assert_eq!(membership(&analyzer, "Listed.cs"), "member");
        assert_eq!(membership(&analyzer, "Extra.cs"), "outside");
    }
    // (label, encoded path fragment, decoded path fragment, invalid XML).
    fn review_r6_references() -> [(&'static str, &'static str, &'static str, bool); 16] {
        [
            ("decimal", "o&#117;t", "out", false),
            ("hex", "o&#x75;t", "out", false),
            ("amp", "a&amp;b", "a&b", false),
            ("lt", "a&lt;b", "a<b", false),
            ("gt", "a&gt;b", "a>b", false),
            ("quot", "a&quot;b", "a\"b", false),
            ("apos", "a&apos;b", "a'b", false),
            ("undefined", "o&unknown;t", "out", true),
            ("custom", "o&custom;t", "out", false),
            ("bad-number", "o&#xZZ;t", "out", true),
            ("unterminated", "o&amp", "out", true),
            ("empty-reference", "o&;t", "out", true),
            ("illegal-xml-char", "o&#1;t", "out", true),
            ("null-char", "o&#0;t", "out", true),
            ("surrogate", "o&#xD800;t", "out", true),
            ("out-of-range", "o&#x110000;t", "out", true),
        ]
    }

    fn review_r6_check(
        analyzer: &CSharpAnalyzer,
        path: &str,
        expected: &str,
        must_gap: bool,
        label: &str,
        failures: &mut Vec<String>,
    ) {
        let actual = membership(analyzer, path);
        let selection = analyzer.selected_compilations().unwrap().unwrap();
        let gaps = selection.gaps().unwrap();
        let valid = if actual == "unproven" {
            !gaps.is_empty()
        } else {
            !must_gap && actual == expected
        };
        eprintln!(
            "R6 {label}: actual={actual} expected={expected} must_gap={must_gap} gaps={gaps:?}"
        );
        if !valid {
            failures.push(format!(
                "{label}: actual={actual}, expected={expected}, must_gap={must_gap}, gaps={gaps:?}"
            ));
        }
    }

    /// [`review_r6_check`] for a reference whose decoded value names a path.
    /// The decoded value is read from the facts the membership rows are
    /// published from, not from a fixture file name: a host file system need
    /// not represent it (Windows refuses `<`, `>` and `"`). The membership SQL
    /// reader is checked for `X.cs`, a source the decoded value does not name,
    /// and must agree with the facts on whether membership is proven.
    fn review_r6_decoded_check(
        xml: &str,
        exact: impl Fn(&CSharpCompileItem) -> bool,
        expected: &str,
        must_gap: bool,
        label: &str,
        failures: &mut Vec<String>,
    ) {
        let facts = facts_of(&[("App.csproj", xml)]);
        let decodes_or_gaps = if facts.membership_complete {
            !must_gap
                && facts
                    .compilations
                    .iter()
                    .flat_map(|compilation| &compilation.items)
                    .any(exact)
        } else {
            !facts.gaps.is_empty()
        };
        let (_root, _, _, analyzer) = analyzed(&[("App.csproj", xml), ("X.cs", "class X {}")]);
        let proven = membership(&analyzer, "X.cs") != "unproven";
        if !decodes_or_gaps || proven != facts.membership_complete {
            failures.push(format!(
                "{label}: decodes_or_gaps={decodes_or_gaps}, proven={proven}, facts={facts:?}"
            ));
        }
        review_r6_check(&analyzer, "X.cs", expected, must_gap, label, failures);
    }

    #[test]
    #[hardwon("#6296: a reference to a character XML 1.0 forbids was accepted")]
    fn review_r6_property_reference_matrix_uses_membership_sql() {
        let mut failures = Vec::new();
        for (label, encoded, decoded, must_gap) in review_r6_references() {
            let dtd = if label == "custom" {
                "<!DOCTYPE Project [<!ENTITY custom 'u'>]>"
            } else {
                ""
            };
            for property in [
                "BaseOutputPath",
                "DefaultItemExcludes",
                "EnableDefaultCompileItems",
            ] {
                let value = match property {
                    "BaseOutputPath" => format!("{encoded}/"),
                    "DefaultItemExcludes" => format!("{encoded}/**/*.cs"),
                    _ => match label {
                        "decimal" => "tr&#117;e".to_owned(),
                        "hex" => "tr&#x75;e".to_owned(),
                        "custom" => "tr&custom;e".to_owned(),
                        _ => encoded.to_owned(),
                    },
                };
                let xml = format!(
                    "{dtd}<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><{property}>{value}</{property}></PropertyGroup></Project>"
                );
                let enables = matches!(label, "decimal" | "hex" | "custom");
                let label = format!("{property}/{label}");
                if property == "EnableDefaultCompileItems" {
                    // The property decides every source alike, so no path
                    // need name the decoded value.
                    let (_root, _, _, analyzer) =
                        analyzed(&[("App.csproj", &xml), ("X.cs", "class X {}")]);
                    review_r6_check(
                        &analyzer,
                        "X.cs",
                        if enables { "member" } else { "outside" },
                        must_gap,
                        &label,
                        &mut failures,
                    );
                } else {
                    // The default tree leaves out the decoded directory.
                    review_r6_decoded_check(
                        &xml,
                        |item| {
                            item.kind == CSharpCompileItemKind::DefaultTree
                                && item.excluded_trees.iter().any(|tree| tree == decoded)
                        },
                        "member",
                        must_gap,
                        &label,
                        &mut failures,
                    );
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon("#6296: a reference to a character XML 1.0 forbids was accepted")]
    fn review_r6_item_attribute_reference_matrix_uses_membership_sql() {
        let mut failures = Vec::new();
        for (label, encoded, decoded, must_gap) in review_r6_references() {
            let dtd = if label == "custom" {
                "<!DOCTYPE Project [<!ENTITY custom 'u'>]>"
            } else {
                ""
            };
            for operation in ["Include", "Remove"] {
                let properties = if operation == "Include" {
                    "<PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup>"
                } else {
                    ""
                };
                let xml = format!(
                    "{dtd}<Project Sdk=\"Microsoft.NET.Sdk\">{properties}<ItemGroup><Compile {operation}=\"{encoded}.cs\"/></ItemGroup></Project>"
                );
                let (kind, expected) = if operation == "Include" {
                    (CSharpCompileItemKind::Include, "outside")
                } else {
                    (CSharpCompileItemKind::Remove, "member")
                };
                // The item carries exactly the decoded path.
                review_r6_decoded_check(
                    &xml,
                    |item| item.kind == kind && item.rel_path == format!("{decoded}.cs"),
                    expected,
                    must_gap,
                    &format!("{operation}/{label}"),
                    &mut failures,
                );
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn review_r6_directory_build_import_trigger_matrix_uses_membership_sql() {
        let mut failures = Vec::new();
        for (label, xml, expected, must_gap, additional) in [
            (
                "sdk-attribute",
                "<Project Sdk=\"Microsoft.NET.Sdk\"/>",
                "member",
                false,
                None,
            ),
            (
                "sdk-element",
                "<Project><Sdk Name=\"Microsoft.NET.Sdk\"/></Project>",
                "member",
                false,
                None,
            ),
            (
                "import-sdk",
                "<Project><Import Project=\"Sdk.props\" Sdk=\"Microsoft.NET.Sdk\"/><Import Project=\"Sdk.targets\" Sdk=\"Microsoft.NET.Sdk\"/></Project>",
                "member",
                false,
                None,
            ),
            (
                "no-common",
                "<Project><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "outside",
                false,
                None,
            ),
            (
                "missing-common-props",
                "<Project><Import Project=\"Microsoft.Common.props\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "unproven",
                true,
                None,
            ),
            (
                "missing-csharp-targets",
                "<Project><Import Project=\"Microsoft.CSharp.targets\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "unproven",
                true,
                None,
            ),
            (
                "dynamic-common-props",
                "<Project><Import Project=\"$(MSBuildExtensionsPath)/Microsoft.Common.props\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "unproven",
                true,
                None,
            ),
            (
                "dynamic-csharp-targets",
                "<Project><Import Project=\"$(MSBuildToolsPath)/Microsoft.CSharp.targets\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "unproven",
                true,
                None,
            ),
            (
                "local-common-props",
                "<Project><Import Project=\"Microsoft.Common.props\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "outside",
                false,
                Some((
                    "Microsoft.Common.props",
                    "<Project><Import Project=\"Directory.Build.props\"/></Project>",
                )),
            ),
            (
                "local-csharp-targets",
                "<Project><Import Project=\"Microsoft.CSharp.targets\"/><ItemGroup><Compile Include=\"Listed.cs\"/></ItemGroup></Project>",
                "member",
                false,
                Some((
                    "Microsoft.CSharp.targets",
                    "<Project><Import Project=\"Directory.Build.targets\"/></Project>",
                )),
            ),
        ] {
            let mut files = vec![
                ("App.csproj", xml),
                ("Listed.cs", "class Listed {}"),
                ("Extra.cs", "class Extra {}"),
                ("Directory.Build.props", "<Project/>"),
                (
                    "Directory.Build.targets",
                    "<Project><ItemGroup><Compile Include=\"Extra.cs\"/></ItemGroup></Project>",
                ),
            ];
            if let Some(file) = additional {
                files.push(file);
            }
            let (_root, _, _, analyzer) = analyzed(&files);
            review_r6_check(
                &analyzer,
                "Extra.cs",
                expected,
                must_gap,
                label,
                &mut failures,
            );
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon("#6296: a reference to a character XML 1.0 forbids was accepted")]
    fn xml_character_boundaries_decide_membership_in_text_and_attributes() {
        // XML 1.0 Char: tab, LF, CR, U+0020-U+D7FF, U+E000-U+FFFD and
        // U+10000-U+10FFFF.
        for (reference, legal) in [
            ("&#x9;", true),
            ("&#xA;", true),
            ("&#xD;", true),
            ("&#x1;", false),
            ("&#x8;", false),
            ("&#x1F;", false),
            ("&#x20;", true),
            ("&#xD7FF;", true),
            ("&#xE000;", true),
            ("&#xFFFD;", true),
            ("&#xFFFE;", false),
            ("&#xFFFF;", false),
            ("&#x10000;", true),
            ("&#x10FFFF;", true),
        ] {
            let property = format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><BaseOutputPath>o{reference}t/</BaseOutputPath></PropertyGroup></Project>"
            );
            let attribute = format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include=\"o{reference}t.cs\" /></ItemGroup></Project>"
            );
            for (project, proven) in [(property, "member"), (attribute, "outside")] {
                let (_root, _, _, analyzer) =
                    analyzed(&[("App.csproj", &project), ("X.cs", "class X {}")]);
                assert_eq!(
                    membership(&analyzer, "X.cs"),
                    if legal { proven } else { "unproven" },
                    "{project}"
                );
            }
        }
    }
    #[test]
    fn review_r7_boundary_values_decode_exactly_or_gap_in_membership_sql() {
        let mut failures = Vec::new();
        for (label, encoded, decoded) in [
            ("tab-decimal", "&#9;", Some('\t')),
            ("lf", "&#xA;", Some('\n')),
            ("cr", "&#xD;", Some('\r')),
            ("control-1f", "&#x1F;", None),
            ("fffe", "&#xFFFE;", None),
            ("ffff", "&#xFFFF;", None),
            ("surrogate", "&#xD800;", None),
            ("max-scalar", "&#x10FFFF;", Some('\u{10FFFF}')),
            ("raw-control", "\u{1}", None),
        ] {
            for context in ["BaseOutputPath", "Include", "Remove"] {
                let xml = match context {
                    "BaseOutputPath" => format!(
                        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><BaseOutputPath>o{encoded}t/</BaseOutputPath></PropertyGroup></Project>"
                    ),
                    "Include" => format!(
                        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include=\"o{encoded}t.cs\"/></ItemGroup></Project>"
                    ),
                    _ => format!(
                        "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Remove=\"o{encoded}t.cs\"/></ItemGroup></Project>"
                    ),
                };
                // The decoded scalar is read from the facts the membership
                // rows are published from, not from a fixture file name: a
                // host file system need not represent it (macOS refuses
                // U+10FFFF, Windows the control characters).
                let facts = facts_of(&[("App.csproj", &xml)]);
                let exact = decoded.is_some_and(|c| {
                    facts
                        .compilations
                        .iter()
                        .flat_map(|compilation| &compilation.items)
                        .any(|item| match context {
                            "BaseOutputPath" => {
                                item.kind == CSharpCompileItemKind::DefaultTree
                                    && item.excluded_trees.contains(&format!("o{c}t"))
                            }
                            "Include" => {
                                item.kind == CSharpCompileItemKind::Include
                                    && item.rel_path == format!("o{c}t.cs")
                            }
                            _ => {
                                item.kind == CSharpCompileItemKind::Remove
                                    && item.rel_path == format!("o{c}t.cs")
                            }
                        })
                });
                let decodes_or_gaps = if facts.membership_complete {
                    exact
                } else {
                    !facts.gaps.is_empty()
                };
                // The membership SQL reader agrees for a source the decoded
                // item does not name.
                let expected = if decoded.is_none() {
                    "unproven"
                } else if context == "Include" {
                    "outside"
                } else {
                    "member"
                };
                let (_root, _, _, analyzer) =
                    analyzed(&[("App.csproj", &xml), ("X.cs", "class X {}")]);
                let actual = membership(&analyzer, "X.cs");
                let gaps = analyzer
                    .selected_compilations()
                    .unwrap()
                    .unwrap()
                    .gaps()
                    .unwrap();
                let correct = actual == expected
                    || (decoded.is_some() && actual == "unproven" && !gaps.is_empty());
                let correct = correct
                    && (actual != "unproven" || !gaps.is_empty())
                    && decodes_or_gaps
                    && (actual == "unproven") == !facts.membership_complete;
                eprintln!(
                    "R7 {context}/{label}: exact={exact}, expected={expected}, actual={actual}, gaps={gaps:?}"
                );
                if !correct {
                    failures.push(format!(
                        "{context}/{label}: exact={exact}, expected={expected}, actual={actual}, facts={facts:?}, gaps={gaps:?}"
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
    #[test]
    #[hardwon("#6296: forbidden XML characters outside membership properties were accepted")]
    fn review_r7_forbidden_xml_text_in_other_properties_is_unproven() {
        let mut failures = Vec::new();
        for (label, text) in [
            ("raw-control", "\u{1}"),
            ("numeric-control", "&#1;"),
            ("hex-control", "&#x1F;"),
            ("forbidden-noncharacter", "&#xFFFF;"),
        ] {
            let xml = format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Description>{text}</Description></PropertyGroup></Project>"
            );
            let (_root, _, _, analyzer) = analyzed(&[("App.csproj", &xml), ("X.cs", "class X {}")]);
            let actual = membership(&analyzer, "X.cs");
            let gaps = analyzer
                .selected_compilations()
                .unwrap()
                .unwrap()
                .gaps()
                .unwrap();
            eprintln!("R7 Description/{label}: actual={actual}, gaps={gaps:?}");
            if actual != "unproven" || gaps.is_empty() {
                failures.push(format!("{label}: actual={actual}, gaps={gaps:?}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon("#6296: forbidden XML characters outside membership properties were accepted")]
    fn every_xml_content_path_is_held_to_xml_characters() {
        let project =
            |content: &str| format!("<Project Sdk=\"Microsoft.NET.Sdk\">{content}</Project>");
        for (content, expected) in [
            // Benign content anywhere keeps the proof.
            (
                "<PropertyGroup><Description>A&amp;B &#x9;caf&#xE9; &#x10FFFF;</Description></PropertyGroup><!-- note --><?pi ok?>",
                "member",
            ),
            (
                "<PropertyGroup><Description><![CDATA[a < b]]></Description></PropertyGroup>",
                "member",
            ),
            (
                "<PropertyGroup><Description>&#xFFFE;</Description></PropertyGroup>",
                "unproven",
            ),
            (
                "<PropertyGroup><Description>&undeclared;</Description></PropertyGroup>",
                "unproven",
            ),
            (
                "<PropertyGroup><Description><![CDATA[\u{1}]]></Description></PropertyGroup>",
                "unproven",
            ),
            (
                "<Target Name=\"T\"><Message Text=\"x\" /></Target>",
                "member",
            ),
            ("<!-- \u{1} -->", "unproven"),
            ("<?pi \u{1}?>", "unproven"),
            (
                "<ItemGroup><None Include=\"a&#x1;b\" /></ItemGroup>",
                "unproven",
            ),
            (
                "<Target Name=\"T\"><Message Text=\"x\" />\u{1}</Target>",
                "unproven",
            ),
        ] {
            let (_root, _, _, analyzer) =
                analyzed(&[("App.csproj", &project(content)), ("X.cs", "class X {}")]);
            assert_eq!(membership(&analyzer, "X.cs"), expected, "{content:?}");
        }
    }
}
