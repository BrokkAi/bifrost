//! Snapshot-only MSBuild property evaluation for selected C# symbols.
use super::*;
use brokk_bifrost_analysis::analyzer::store::csharp_compilation::CSharpSymbolEnvironment;

type Properties = HashMap<String, Result<String, &'static str>>;

pub(super) fn expand(value: &str, properties: &Properties) -> Result<String, &'static str> {
    // MSBuild property values, never C# syntax. Functions and item transforms
    // require MSBuild evaluation and cannot be inferred from their spelling.
    if value.contains("$([") || value.contains("@(") || value.contains("%(") {
        return Err("dynamic_property");
    }
    let mut result = String::new();
    let mut tail = value;
    while let Some(start) = tail.find("$(") {
        result.push_str(&tail[..start]);
        let rest = &tail[start + 2..];
        let end = rest.find(')').ok_or("dynamic_property")?;
        let replacement = properties
            .get(&rest[..end].to_ascii_lowercase())
            .ok_or("dynamic_property")?
            .as_ref()
            .map_err(|reason| *reason)?;
        result.push_str(replacement);
        tail = &rest[end + 1..];
        if result.len() > MAX_PROJECT_BYTES {
            return Err("dynamic_property");
        }
    }
    result.push_str(tail);
    Ok(result)
}

// The caller already expanded the supported import chain and retained any
// unresolved imports as membership obligations. Reuse the symbol evaluator's
// scalar operations and expansion; these values describe the declared workspace.
pub(super) fn membership_properties<'a>(
    sources: impl Iterator<Item = &'a str>,
) -> Result<Properties, &'static str> {
    membership_properties_with_globals(sources, &[])
}

// Preserve the structurally selected raw assignment for diagnostics when its
// value cannot be expanded. It never contributes to a project-scope proof.
pub(super) fn raw_target_frameworks<'a>(sources: impl Iterator<Item = &'a str>) -> Option<String> {
    sources
        .filter_map(|source| operations(source).ok())
        .flatten()
        .filter_map(|operation| match operation {
            Operation::Property(name, Ok(value))
                if name.eq_ignore_ascii_case("targetframeworks") =>
            {
                Some(value)
            }
            _ => None,
        })
        .last()
}

pub(super) fn membership_properties_with_globals<'a>(
    sources: impl Iterator<Item = &'a str>,
    globals: &[(&str, &str)],
) -> Result<Properties, &'static str> {
    let mut properties = initial_properties();
    for &(name, value) in globals {
        properties.insert(name.to_ascii_lowercase(), Ok(value.to_owned()));
    }
    // Fill this SDK fallback after workspace assignments; a self-reference
    // without a declared prior value must not invent an inside-project path.
    for source in sources {
        for operation in operations(source)? {
            match operation {
                Operation::Property(name, value) => {
                    let name = name.to_ascii_lowercase();
                    if globals
                        .iter()
                        .any(|(global, _)| name.eq_ignore_ascii_case(global))
                    {
                        continue;
                    }
                    if !matches!(properties.get(&name), Some(Err("target_assignment"))) {
                        let value = value.and_then(|value| expand(&value, &properties));
                        properties.insert(name, value);
                    }
                }
                Operation::TargetProperty(name) => {
                    if globals
                        .iter()
                        .any(|(global, _)| name.eq_ignore_ascii_case(global))
                    {
                        continue;
                    }
                    properties.insert(name, Err("target_assignment"));
                }
                Operation::TreatAsLocalProperty if !globals.is_empty() => {
                    return Err("treat_as_local_property");
                }
                Operation::TreatAsLocalProperty => {}
                Operation::Import(_) => {}
            }
        }
    }
    // These optional SDK suffixes cannot make an in-project default escape.
    // Unmodeled artifacts defaults can choose a different base entirely.
    for (name, label) in [
        ("platform", "Platform"),
        ("platformname", "PlatformName"),
        (
            "_platformtoappendtooutputpath",
            "_PlatformToAppendToOutputPath",
        ),
        ("runtimeidentifier", "RuntimeIdentifier"),
    ] {
        if let Some(value) = properties.get(name) {
            let value = value.as_ref().map_err(|_| label)?;
            if !value.is_empty()
                && (!static_item_path(value)
                    || value.contains(':')
                    || resolve_item_path(Path::new(""), value).is_none())
            {
                return Err(label);
            }
        }
    }
    for name in ["useartifactsoutput", "useartifactsintermediateoutput"] {
        if properties.get(name).is_some_and(|value| {
            !value
                .as_ref()
                .is_ok_and(|value| value.is_empty() || value.eq_ignore_ascii_case("false"))
        }) {
            return Err("BaseIntermediateOutputPath (SDK artifacts layout)");
        }
    }
    if properties
        .get("artifactspath")
        .is_some_and(|value| !value.as_ref().is_ok_and(String::is_empty))
    {
        return Err("BaseIntermediateOutputPath (ArtifactsPath layout)");
    }
    for (name, value) in [
        ("appdesignerfolder", "Properties"),
        ("baseintermediateoutputpath", "obj/"),
        ("configuration", "Debug"),
    ] {
        if properties
            .get(name)
            .is_none_or(|value| value.as_ref().is_ok_and(|value| value.trim().is_empty()))
        {
            properties.insert(name.into(), Ok(value.into()));
        }
    }
    if let Some(Ok(base)) = properties.get_mut("baseintermediateoutputpath")
        && !base.ends_with(['/', '\\'])
    {
        base.push('/');
    }
    if properties
        .get("intermediateoutputpath")
        .is_none_or(|value| value.as_ref().is_ok_and(|value| value.trim().is_empty()))
    {
        let platform = properties
            .get("platformname")
            .or_else(|| properties.get("platform"))
            .and_then(|value| value.as_ref().ok())
            .map(String::as_str)
            .unwrap_or("AnyCPU");
        let append = properties
            .get("appendplatformtooutputpath")
            .map(|value| {
                value
                    .as_ref()
                    .map(|value| value.eq_ignore_ascii_case("true"))
                    .map_err(|_| "AppendPlatformToOutputPath")
            })
            .transpose()?
            .unwrap_or(!platform.eq_ignore_ascii_case("AnyCPU"));
        let prefix = if append {
            format!("{platform}/")
        } else {
            properties
                .get("_platformtoappendtooutputpath")
                .and_then(|value| value.as_ref().ok())
                .cloned()
                .unwrap_or_default()
        };
        let value = expand(
            &format!("$(BaseIntermediateOutputPath){prefix}$(Configuration)/"),
            &properties,
        )
        .and_then(|mut value| {
            let framework = properties
                .get("targetframework")
                .ok_or("dynamic_property")?
                .as_ref()
                .map_err(|_| "dynamic_property")?;
            value.push_str(&framework.to_ascii_lowercase());
            value.push('/');
            Ok(value)
        });
        properties.insert("intermediateoutputpath".into(), value);
    }
    Ok(properties)
}

fn initial_properties() -> Properties {
    [
        ("configuration", "Debug"),
        ("defineconstants", ""),
        ("disableimplicitconfigurationdefines", "false"),
        ("disablediagnostictracing", "false"),
        ("baseintermediateoutputpath", "obj/"),
        ("disableimplicitframeworkdefines", "false"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), Ok(value.into())))
    .collect()
}

// One bounded XML document, in evaluation order. Imports are expanded by the
// outer worklist at their exact position, not before the importing document.
#[derive(Debug)]
enum Operation {
    Property(String, Result<String, &'static str>),
    TargetProperty(String),
    TreatAsLocalProperty,
    Import(Result<String, &'static str>),
}
fn operations(source: &str) -> Result<Vec<Operation>, &'static str> {
    let mut reader = Reader::from_str(source);
    let mut stack: Vec<(String, bool, String)> = Vec::new();
    let mut result = Vec::new();
    let mut nodes = 0;
    loop {
        let event = reader.read_event().map_err(|_| "dynamic_property")?;
        nodes += 1;
        if nodes > MAX_XML_NODES || stack.len() > MAX_XML_DEPTH {
            return Err("dynamic_property");
        }
        match event {
            Event::Start(ref element) | Event::Empty(ref element) => {
                let name = msbuild_name(element.name().as_ref()).ok_or("dynamic_property")?;
                if stack.len() >= 2 && stack[stack.len() - 2].0 == "propertygroup" {
                    return Err("dynamic_property");
                }
                let in_target = stack.iter().any(|frame| frame.0 == "target");
                let mut condition = stack
                    .last()
                    .is_some_and(|frame| frame.1 || frame.0 == "choose");
                let mut import = None;
                let mut output_property = None;
                let mut qualified_import = false;
                let mut treat_as_local = false;
                for attr in element.attributes() {
                    let attr = attr.map_err(|_| "dynamic_property")?;
                    let value = attr
                        .decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            reader.decoder(),
                        )
                        .map_err(|_| "dynamic_property")?
                        .into_owned();
                    let key = msbuild_name(attr.key.as_ref()).ok_or("dynamic_property")?;
                    match key.as_str() {
                        "treataslocalproperty" if name == "project" => {
                            treat_as_local = true;
                        }
                        "condition" => condition = true,
                        "project" if name == "import" => import = Some(value),
                        "propertyname" if name == "output" => output_property = Some(value),
                        "sdk" | "version" | "minimumversion" if name == "import" => {
                            qualified_import = true
                        }
                        _ => {}
                    }
                }
                if treat_as_local {
                    result.push(Operation::TreatAsLocalProperty);
                }
                if in_target
                    && name == "output"
                    && let Some(property) = output_property
                {
                    // MSBuild expands this destination at target execution time.
                    // Another target can change an expansion input after evaluation.
                    if property.is_empty()
                        || !property.chars().enumerate().all(|(index, ch)| {
                            ch == '_'
                                || ch.is_ascii_alphabetic()
                                || (index > 0 && ch.is_ascii_digit())
                        })
                    {
                        return Err("dynamic_target_property");
                    }
                    result.push(Operation::TargetProperty(property.to_ascii_lowercase()));
                }
                if name == "import" && !in_target {
                    result.push(Operation::Import(if qualified_import {
                        Err("unevaluated_import")
                    } else if condition {
                        Err("condition")
                    } else {
                        import.ok_or("unevaluated_import")
                    }));
                }
                if matches!(event, Event::Start(_)) {
                    stack.push((name, condition, String::new()));
                } else if stack.last().is_some_and(|frame| frame.0 == "propertygroup") {
                    if in_target {
                        result.push(Operation::TargetProperty(name.to_ascii_lowercase()));
                    } else {
                        result.push(Operation::Property(
                            name.to_ascii_lowercase(),
                            if condition {
                                Err("condition")
                            } else {
                                Ok(String::new())
                            },
                        ));
                    }
                }
            }
            Event::Text(text) => {
                if let Some(frame) = stack.last_mut() {
                    let decoded = text.decode().map_err(|_| "dynamic_property")?;
                    frame.2.push_str(
                        &quick_xml::escape::unescape(&decoded).map_err(|_| "dynamic_property")?,
                    );
                }
            }
            Event::CData(text) => {
                if let Some(frame) = stack.last_mut() {
                    frame
                        .2
                        .push_str(&text.decode().map_err(|_| "dynamic_property")?);
                }
            }
            Event::End(_) => {
                let (name, condition, value) = stack.pop().ok_or("dynamic_property")?;
                if stack.last().is_some_and(|frame| frame.0 == "propertygroup") {
                    if stack.iter().any(|frame| frame.0 == "target") {
                        result.push(Operation::TargetProperty(name.to_ascii_lowercase()));
                    } else {
                        result.push(Operation::Property(
                            name.to_ascii_lowercase(),
                            if condition {
                                Err("condition")
                            } else {
                                Ok(value)
                            },
                        ));
                    }
                }
            }
            Event::Eof => break,
            Event::DocType(_) | Event::GeneralRef(_) => return Err("dynamic_property"),
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("dynamic_property");
    }
    Ok(result)
}

fn nearest<'a>(
    inputs: &'a [CSharpConfigurationInput],
    project: &str,
    name: &str,
) -> Option<&'a str> {
    let mut dir = Path::new(project).parent();
    while let Some(directory) = dir {
        let path = portable_rel_path(&directory.join(name));
        if let Some(input) = inputs.iter().find(|input| {
            input.rel_path == path
                && input
                    .source
                    .as_deref()
                    .is_none_or(|bytes| !bytes.is_empty())
        }) {
            return Some(&input.rel_path);
        }
        dir = directory.parent();
    }
    None
}

fn evaluate(
    inputs: &[CSharpConfigurationInput],
    paths: &[&str],
    properties: &mut Properties,
) -> Result<(), &'static str> {
    let mut work = paths
        .iter()
        .rev()
        .map(|path| (path.to_string(), 0, None))
        .collect::<Vec<_>>();
    let mut count = 0;
    let mut open_reason = None;
    while let Some((path, depth, operation)) = work.pop() {
        count += 1;
        if depth > MAX_IMPORT_DEPTH || count > MAX_XML_NODES {
            return Err("unevaluated_import");
        }
        if let Some(operation) = operation {
            match operation {
                Operation::Property(name, value) => {
                    if name == "configuration" {
                        continue;
                    } // Selected global property.
                    if matches!(properties.get(&name), Some(Err("target_assignment"))) {
                        continue;
                    }
                    let value = value.and_then(|value| expand(&value, properties));
                    // Conditions remain unknown even if a later assignment
                    // happens to overwrite the same property.
                    if let Err(reason) = &value {
                        open_reason.get_or_insert(*reason);
                    }
                    properties.insert(name, value);
                }
                Operation::TargetProperty(name) => {
                    properties.insert(name, Err("target_assignment"));
                }
                Operation::TreatAsLocalProperty => {}
                Operation::Import(value) => {
                    let value = expand(&value?, properties).map_err(|_| "unevaluated_import")?;
                    // A drive-qualified or rooted import is external even on
                    // hosts where Path does not recognize its foreign prefix.
                    if !static_item_path(&value)
                        || value.contains(':')
                        || value.starts_with(['/', '\\'])
                    {
                        return Err("unevaluated_import");
                    }
                    let import =
                        resolve_item_path(Path::new(&path).parent().expect("input parent"), &value)
                            .ok_or("unevaluated_import")?;
                    work.push((portable_rel_path(&import), depth + 1, None));
                }
            }
        } else {
            let source = inputs
                .iter()
                .find(|input| input.rel_path == path)
                .and_then(|input| input.source.as_deref())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .ok_or("unevaluated_import")?;
            for operation in operations(source)?.into_iter().rev() {
                work.push((path.clone(), depth, Some(operation)));
            }
        }
    }
    open_reason.map_or(Ok(()), Err)
}

fn project_paths<'a>(inputs: &'a [CSharpConfigurationInput], project: &'a str) -> Vec<&'a str> {
    let mut paths = Vec::new();
    if let Some(path) = nearest(inputs, project, "Directory.Build.props") {
        paths.push(path);
    }
    if let Some(path) = nearest(inputs, project, "Directory.Packages.props") {
        paths.push(path);
    }
    paths.push(project);
    if let Some(path) = nearest(inputs, project, "Directory.Build.targets") {
        paths.push(path);
    }
    paths
}

pub(super) fn derive(
    inputs: &[CSharpConfigurationInput],
    project: Option<&str>,
) -> CSharpSymbolEnvironment {
    let mut environment = CSharpSymbolEnvironment::default();
    let Some(project) = project else {
        return environment;
    };
    let mut properties = initial_properties();
    let result = (|| {
        let source = inputs
            .iter()
            .find(|input| input.rel_path == project)
            .and_then(|input| input.source.as_deref())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or("dynamic_property")?;
        let parsed = parse_project(source);
        if parsed.sdks != ["Microsoft.NET.Sdk"] {
            return Err("unevaluated_import");
        }
        let mut property_reason = None;
        if let Some(props) = nearest(inputs, project, "Directory.Build.props") {
            property_reason = evaluate(inputs, &[props], &mut properties).err();
        }
        if let Some(packages) = nearest(inputs, project, "Directory.Packages.props")
            && let Err(reason) = evaluate(inputs, &[packages], &mut properties)
        {
            property_reason.get_or_insert(reason);
        }
        let defines = properties
            .get("defineconstants")
            .expect("default defines")
            .as_ref()
            .map(|defines| format!("{defines};TRACE"))
            .map_err(|reason| *reason);
        properties.insert("defineconstants".into(), defines);
        let mut body = vec![project];
        if let Some(targets) = nearest(inputs, project, "Directory.Build.targets") {
            body.push(targets);
        }
        if let Err(reason) = evaluate(inputs, &body, &mut properties) {
            property_reason.get_or_insert(reason);
        }
        let intermediate = properties
            .get("baseintermediateoutputpath")
            .expect("default path")
            .as_ref()
            .map_err(|reason| *reason)?;
        let directory = resolve_item_path(
            Path::new(project).parent().expect("project parent"),
            intermediate,
        )
        .ok_or("dynamic_property")?;
        let assets_path = portable_rel_path(&directory.join("project.assets.json"));
        let assets = inputs
            .iter()
            .find(|input| input.rel_path == assets_path)
            .and_then(|input| input.source.as_deref())
            .filter(|source| !source.is_empty())
            .ok_or("unrestored")?;
        let assets: serde_json::Value = serde_json::from_slice(assets).map_err(|_| "unrestored")?;
        // SDK 10.0.403 restore writes this array in sorted order, including
        // when TargetFrameworks was declared in the opposite order (oracle).
        let framework = assets
            .pointer("/project/restore/originalTargetFrameworks")
            .and_then(serde_json::Value::as_array)
            .and_then(|values| values.first())
            .and_then(serde_json::Value::as_str)
            .ok_or("unrestored")?;
        environment.target_framework = Some(framework.to_owned());
        for suffix in ["props", "targets"] {
            let path = portable_rel_path(&directory.join(format!(
                    "{}.nuget.g.{suffix}",
                    Path::new(project)
                        .file_name()
                        .expect("project file")
                        .to_string_lossy()
                )));
            let source = inputs
                .iter()
                .find(|input| input.rel_path == path)
                .and_then(|input| input.source.as_deref())
                .filter(|source| !source.is_empty())
                .ok_or("unrestored")?;
            let source = std::str::from_utf8(source).map_err(|_| "unevaluated_import")?;
            let generated = operations(source)?;
            if generated
                .iter()
                .any(|op| matches!(op, Operation::Import(_)))
            {
                return Err("package_build_import");
            }
            // NuGet's generated metadata properties do not contribute defines.
            // A modified/generated file with additional property assignments is
            // an unevaluated source, rather than evidence for a closed set.
            if generated.iter().any(|op| matches!(op, Operation::Property(name, _) if !matches!(name.as_str(), "restoresuccess" | "restoretool" | "projectassetsfile" | "nugetpackageroot" | "nugetpackagefolders" | "nugetprojectstyle" | "nugettoolversion" | "msbuildallprojects"))) {
                return Err("unevaluated_import");
            }
        }
        if let Some(reason) = property_reason {
            return Err(reason);
        }
        for property in [
            "targetframeworkidentifier",
            "targetframeworkversion",
            "targetplatformidentifier",
            "targetplatformversion",
            "frameworkpathoverride",
            "msbuildprojectextensionspath",
            "importdirectorybuildprops",
            "importdirectorybuildtargets",
            "custombeforemicrosoftcommontargets",
            "customaftermicrosoftcommontargets",
            "languagetargets",
            "directorybuildpropspath",
            "directorybuildtargetspath",
            "directorypackagespropspath",
            "importdirectorypackagesprops",
            "custombeforemicrosoftcommonprops",
            "customaftermicrosoftcommonprops",
            "nugetpropsfile",
            "importprojectextensionprops",
            "importprojectextensiontargets",
            "excluderestorepackageimports",
        ] {
            if properties.contains_key(&property.to_ascii_lowercase()) {
                return Err("unevaluated_import");
            }
        }
        let mut symbols = std::collections::BTreeMap::new();
        let constants = properties
            .get("defineconstants")
            .expect("default defines")
            .as_ref()
            .map_err(|reason| *reason)?;
        for symbol in constants
            .split(|ch: char| ch == ';' || ch == ',' || ch.is_whitespace())
            .filter(|symbol| !symbol.is_empty())
        {
            if !symbol.chars().enumerate().all(|(index, ch)| {
                ch == '_' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
            }) {
                return Err("dynamic_property");
            }
            symbols.insert(symbol.to_owned(), "define_constants".to_owned());
        }
        // Microsoft.NET.Sdk.BeforeCommon.targets SDK 10.0.403:188-207 names
        // framework defines, :234-247 adds compatible versions, :290-295
        // appends them at target execution. Unevaluated imports/targets may
        // overwrite DefineConstants, so OPEN ENVIRONMENTS LIST NO SYMBOLS.
        // CSharp.props:21-22 appends TRACE before the project body; SDK CSharp.targets:16-31
        // appends the configuration symbol. The table version enters both set derivation
        // and the environment digest. Never consult an installed SDK here.
        let framework_symbols = implicit_symbols(framework)?;
        if !properties
            .get("disableimplicitframeworkdefines")
            .expect("default implicit")
            .as_ref()
            .map_err(|reason| *reason)?
            .eq_ignore_ascii_case("true")
        {
            for symbol in framework_symbols {
                symbols.insert(symbol, "sdk".to_owned());
            }
        }
        // Microsoft.NET.Sdk.CSharp.targets:16-31 appends the configuration
        // define after the project and Directory.Build.targets are evaluated.
        if !properties
            .get("disableimplicitconfigurationdefines")
            .expect("configuration default")
            .as_ref()
            .map_err(|reason| *reason)?
            .eq_ignore_ascii_case("true")
        {
            symbols.insert("DEBUG".into(), "sdk".into());
        }
        if properties
            .get("disablediagnostictracing")
            .expect("tracing default")
            .as_ref()
            .map_err(|reason| *reason)?
            .eq_ignore_ascii_case("true")
        {
            symbols.remove("TRACE");
        }
        if symbols.contains_key("TRACE") {
            symbols.insert("TRACE".into(), "sdk".into());
        }
        environment.symbols = symbols.into_iter().collect();
        Ok(())
    })();
    environment.open_reason = result.err().map(str::to_owned);
    environment
}

// SDK 10.0.403: Microsoft.NET.Sdk.BeforeCommon.targets:188-207 generates
// framework names, :234-247 compatible versions, :290-295 appends the symbols.
// Microsoft.NET.SupportedTargetFrameworks.props supplies the version tables.
// CSharp.props:21-22 appends TRACE; CSharp.targets:16-31 appends DEBUG.
// Unevaluated targets can overwrite DefineConstants at execution time, so an
// open environment lists NO symbols. Table identity is versioned in the store.
fn implicit_symbols(framework: &str) -> Result<Vec<String>, &'static str> {
    const CORE: &[&str] = &[
        "1.0", "1.1", "2.0", "2.1", "2.2", "3.0", "3.1", "5.0", "6.0", "7.0", "8.0", "9.0", "10.0",
    ];
    const STANDARD: &[&str] = &[
        "1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "2.0", "2.1",
    ];
    const FRAMEWORK: &[&str] = &[
        "20", "30", "35", "40", "45", "451", "452", "46", "461", "462", "47", "471", "472", "48",
        "481",
    ];
    // Microsoft.NET.SupportedTargetFrameworks.props: _NETCoreAppVersionsForDefines,
    // SupportedNETStandardTargetFramework, SupportedNETFrameworkTargetFramework.
    let (prefix, version, versions, versionless) =
        if let Some(version) = framework.strip_prefix("netstandard") {
            ("NETSTANDARD", version, STANDARD, "NETSTANDARD")
        } else if let Some(version) = framework.strip_prefix("netcoreapp") {
            ("NETCOREAPP", version, CORE, "NETCOREAPP")
        } else if let Some(version) = framework.strip_prefix("net") {
            if version.contains('.') {
                ("NET", version, CORE, "NET")
            } else {
                ("NET", version, FRAMEWORK, "NETFRAMEWORK")
            }
        } else {
            return Err("unsupported_framework");
        };
    let index = versions
        .iter()
        .position(|candidate| *candidate == version)
        .ok_or("unsupported_framework")?;
    let mut symbols = vec![
        versionless.into(),
        format!("{prefix}{}", version.replace('.', "_")),
    ];
    if prefix == "NET" && version.contains('.') {
        symbols.push("NETCOREAPP".into());
    }
    for (position, version) in versions[..=index].iter().enumerate() {
        let compatible_prefix = if prefix == "NET" && version.contains('.') && position < 7 {
            "NETCOREAPP"
        } else {
            prefix
        };
        symbols.push(format!(
            "{compatible_prefix}{}_OR_GREATER",
            version.replace('.', "_")
        ));
    }
    Ok(symbols)
}

pub(crate) fn capture_ancestor_configuration_paths(
    project: &dyn Project,
    files: &BTreeSet<ProjectFile>,
    inputs: &mut BTreeSet<ProjectFile>,
) {
    for file in files
        .iter()
        .filter(|file| has_extension(file.rel_path(), "csproj"))
    {
        for directory in file
            .rel_path()
            .parent()
            .expect("project parent")
            .ancestors()
        {
            for name in [
                "Directory.Build.props",
                "Directory.Build.targets",
                "Directory.Packages.props",
            ] {
                inputs.insert(ProjectFile::new(project.root(), directory.join(name)));
            }
        }
    }
}

pub(crate) fn restore_paths_from_retained_inputs(
    inputs: &[brokk_bifrost_analysis::analyzer::store::WorkspaceConfigurationInput],
) -> Vec<PathBuf> {
    let configuration = inputs
        .iter()
        .map(|input| CSharpConfigurationInput {
            rel_path: input.relative_path().to_owned(),
            source: Some(input.source_bytes().to_vec()),
        })
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    for file in inputs
        .iter()
        .filter(|input| has_extension(Path::new(input.relative_path()), "csproj"))
    {
        let path = file.relative_path();
        let mut properties = initial_properties();
        let evaluation_open = evaluate(
            &configuration,
            &project_paths(&configuration, path),
            &mut properties,
        )
        .is_err();
        let intermediate = properties
            .get("baseintermediateoutputpath")
            .and_then(|value| value.as_ref().ok())
            .map(String::as_str)
            .unwrap_or("obj/");
        let project_path = Path::new(path);
        let directory = project_path.parent().expect("project parent");
        let mut directories = resolve_item_path(directory, intermediate)
            .into_iter()
            .collect::<Vec<_>>();
        if evaluation_open {
            directories.push(directory.join("obj"));
        }
        for directory in directories {
            paths.push(directory.join("project.assets.json"));
            for suffix in ["props", "targets"] {
                paths.push(directory.join(format!(
                        "{}.nuget.g.{suffix}",
                        project_path
                            .file_name()
                            .expect("project name")
                            .to_string_lossy()
                    )));
            }
        }
    }
    paths
}
