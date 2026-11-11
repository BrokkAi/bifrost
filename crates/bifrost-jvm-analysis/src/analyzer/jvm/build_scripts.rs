//! Structural readers for the build definitions of Gradle and sbt projects
//! (#9325): Kotlin DSL scripts through the Kotlin grammar and `build.sbt`
//! through the Scala grammar, never by scanning their text. Only literal
//! arguments are interpreted; anything a build would have to evaluate is
//! returned as an unread span for the caller to report.
//!
//! Gradle's Groovy DSL has no grammar in Bifrost, so `build.gradle` and
//! `settings.gradle` are not read here.

use std::ops::Range;

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;
use brokk_bifrost_jvm::kotlin::declarations::kotlin_identifier_text;
use brokk_bifrost_jvm::kotlin::syntax::kotlin_plain_string_literal;
use tree_sitter::{Node, Parser, Tree};

/// A construct a reader saw and does not interpret, with why.
pub(crate) type Unread = (Range<usize>, String);

fn parse(language: tree_sitter::Language, source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .expect("the pinned JVM grammars load");
    let tree = parser.parse(source, None)?;
    // A recovered tree may have moved a declaration into an ERROR node, so
    // no answer drawn from it can claim to be the file's.
    (!tree.root_node().has_error()).then_some(tree)
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == kind)
}

fn text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    &source[node.byte_range()]
}

/// `include` entries and the root name of a `settings.gradle.kts`.
#[derive(Debug, Default)]
pub(crate) struct GradleSettings {
    pub(crate) root_name: Option<String>,
    /// Gradle project paths as written (`app`, `:lib:core`).
    pub(crate) includes: Vec<(String, Range<usize>)>,
    pub(crate) unread: Vec<Unread>,
}

/// The project-scope declarations of one `build.gradle.kts`.
#[derive(Debug, Default)]
pub(crate) struct GradleBuild {
    /// Applied plugin ids; `kotlin("jvm")` is `org.jetbrains.kotlin.jvm`.
    pub(crate) plugins: Vec<String>,
    pub(crate) declarations: Vec<GradleDeclaration>,
    /// `jvmToolchain(N)` and `JavaLanguageVersion.of(N)` arguments.
    pub(crate) toolchains: Vec<(String, Range<usize>)>,
    pub(crate) unread: Vec<Unread>,
}

#[derive(Debug)]
pub(crate) struct GradleDeclaration {
    /// The configuration the dependency is added to (`implementation`).
    pub(crate) configuration: String,
    pub(crate) range: Range<usize>,
    pub(crate) target: GradleTarget,
    /// `platform` or `enforcedPlatform`: a BOM, not a library.
    pub(crate) platform: Option<&'static str>,
}

#[derive(Debug)]
pub(crate) enum GradleTarget {
    Module {
        group: String,
        name: String,
        version: Option<String>,
        /// Written as `kotlin("x")`, whose version defaults to the Kotlin
        /// plugin's.
        kotlin_notation: bool,
    },
    /// A version-catalog accessor below `libs`, dot-joined (`commons.text`).
    Catalog(String),
    /// Another project of the build, by Gradle path.
    Project(String),
}

fn kotlin_language() -> tree_sitter::Language {
    brokk_bifrost_jvm::kotlin::language::LANGUAGE.into()
}

/// The callee name and the suffix of a Kotlin call with a simple callee.
fn kotlin_call<'tree>(node: Node<'tree>, source: &str) -> Option<(String, Node<'tree>)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let children = named_children(node);
    let [callee, suffix] = children.as_slice() else {
        return None;
    };
    (callee.kind() == "simple_identifier" && suffix.kind() == "call_suffix")
        .then(|| (kotlin_identifier_text(*callee, source).to_owned(), *suffix))
}

fn kotlin_arguments(suffix: Node<'_>) -> Vec<Node<'_>> {
    child_of_kind(suffix, "value_arguments")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| argument.kind() == "value_argument")
        .collect()
}

fn kotlin_lambda_statements(suffix: Node<'_>) -> Vec<Node<'_>> {
    child_of_kind(suffix, "annotated_lambda")
        .and_then(|lambda| child_of_kind(lambda, "lambda_literal"))
        .and_then(|lambda| child_of_kind(lambda, "statements"))
        .map(named_children)
        .unwrap_or_default()
}

/// The label and value of one `value_argument`: `name = value` or `value`.
fn kotlin_argument<'tree>(argument: Node<'tree>, source: &str) -> (Option<String>, Node<'tree>) {
    let children = named_children(argument);
    let mut cursor = argument.walk();
    let labelled = children.len() == 2
        && children[0].kind() == "simple_identifier"
        && argument
            .children(&mut cursor)
            .any(|child| !child.is_named() && child.kind() == "=");
    if labelled {
        (
            Some(kotlin_identifier_text(children[0], source).to_owned()),
            children[1],
        )
    } else {
        (
            None,
            *children.last().expect("a value_argument has a value"),
        )
    }
}

/// The unlabelled plain string arguments of a call, or `None` when any
/// argument is something else.
fn kotlin_string_arguments<'source>(
    suffix: Node<'_>,
    source: &'source str,
) -> Option<Vec<&'source str>> {
    kotlin_arguments(suffix)
        .into_iter()
        .map(|argument| match kotlin_argument(argument, source) {
            (None, value) => kotlin_plain_string_literal(value, source),
            _ => None,
        })
        .collect()
}

pub(crate) fn read_gradle_settings(source: &str) -> Option<GradleSettings> {
    let tree = parse(kotlin_language(), source)?;
    let mut settings = GradleSettings::default();
    for statement in named_children(tree.root_node()) {
        match statement.kind() {
            "assignment" => {
                let children = named_children(statement);
                let [target, value] = children.as_slice() else {
                    continue;
                };
                let segments = named_children(*target)
                    .into_iter()
                    .map(|segment| match segment.kind() {
                        "navigation_suffix" => child_of_kind(segment, "simple_identifier")
                            .map(|name| kotlin_identifier_text(name, source)),
                        "simple_identifier" => Some(kotlin_identifier_text(segment, source)),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>();
                match segments.as_deref() {
                    Some(["rootProject", "name"]) => {
                        match kotlin_plain_string_literal(*value, source) {
                            Some(name) => settings.root_name = Some(name.to_owned()),
                            None => settings.unread.push((
                                statement.byte_range(),
                                "rootProject.name is not a plain string".to_owned(),
                            )),
                        }
                    }
                    Some([.., "projectDir"]) => settings.unread.push((
                        statement.byte_range(),
                        "a custom projectDir moves a project away from its path".to_owned(),
                    )),
                    _ => {}
                }
            }
            "call_expression" => {
                let Some((name, suffix)) = kotlin_call(statement, source) else {
                    continue;
                };
                match name.as_str() {
                    "include" => {
                        for argument in kotlin_arguments(suffix) {
                            let path = match kotlin_argument(argument, source) {
                                (None, value) => kotlin_plain_string_literal(value, source),
                                _ => None,
                            };
                            match path {
                                Some(path) => settings
                                    .includes
                                    .push((path.to_owned(), argument.byte_range())),
                                None => settings.unread.push((
                                    argument.byte_range(),
                                    "an include argument is not a plain string".to_owned(),
                                )),
                            }
                        }
                    }
                    "includeBuild" => settings.unread.push((
                        statement.byte_range(),
                        "an included build is a separate build this reader does not follow"
                            .to_owned(),
                    )),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Some(settings)
}

pub(crate) fn read_gradle_build(source: &str) -> Option<GradleBuild> {
    let tree = parse(kotlin_language(), source)?;
    let mut build = GradleBuild::default();
    let mut kotlin_plugin_version = None;
    for statement in named_children(tree.root_node()) {
        let Some((name, suffix)) = kotlin_call(statement, source) else {
            continue;
        };
        match name.as_str() {
            "plugins" => {
                for plugin in kotlin_lambda_statements(suffix) {
                    // `id("x") version "1.0"` is an infix call on the request.
                    let (request, version) = match named_children(plugin).as_slice() {
                        [request, operator, version]
                            if plugin.kind() == "infix_expression"
                                && operator.kind() == "simple_identifier"
                                && text(*operator, source) == "version" =>
                        {
                            (*request, kotlin_plain_string_literal(*version, source))
                        }
                        _ => (plugin, None),
                    };
                    if request.kind() == "simple_identifier" {
                        build
                            .plugins
                            .push(kotlin_identifier_text(request, source).to_owned());
                        continue;
                    }
                    let Some((callee, inner)) = kotlin_call(request, source) else {
                        continue;
                    };
                    let arguments = kotlin_string_arguments(inner, source);
                    let Some([id]) = arguments.as_deref() else {
                        continue;
                    };
                    match callee.as_str() {
                        "id" => build.plugins.push((*id).to_owned()),
                        "kotlin" => {
                            build.plugins.push(format!("org.jetbrains.kotlin.{id}"));
                            kotlin_plugin_version =
                                kotlin_plugin_version.or(version.map(str::to_owned));
                        }
                        _ => {}
                    }
                }
            }
            "dependencies" => {
                for declaration in kotlin_lambda_statements(suffix) {
                    match gradle_declaration(declaration, source) {
                        Ok(declaration) => build.declarations.push(declaration),
                        Err(reason) => build.unread.push((declaration.byte_range(), reason)),
                    }
                }
            }
            // Its dependencies are the build's own classpath, not the
            // program's.
            "buildscript" => {}
            _ => {
                // `subprojects { dependencies { ... } }` and its kind
                // configure other projects; say so rather than misattribute.
                let mut stack = vec![suffix];
                while let Some(node) = stack.pop() {
                    if kotlin_call(node, source).is_some_and(|(inner, _)| inner == "dependencies") {
                        build.unread.push((
                            node.byte_range(),
                            format!(
                                "dependencies declared inside {name} {{ }} are not attributed to a project"
                            ),
                        ));
                        continue;
                    }
                    stack.extend(named_children(node));
                }
            }
        }
    }
    // Toolchain requests may sit in `kotlin { }` or `java { toolchain { } }`.
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        stack.extend(named_children(node));
        let children = named_children(node);
        let [callee, suffix] = children.as_slice() else {
            continue;
        };
        let named = node.kind() == "call_expression"
            && suffix.kind() == "call_suffix"
            && match callee.kind() {
                "simple_identifier" => kotlin_identifier_text(*callee, source) == "jvmToolchain",
                "navigation_expression" => text(*callee, source) == "JavaLanguageVersion.of",
                _ => false,
            };
        if named
            && let [argument] = kotlin_arguments(*suffix).as_slice()
            && let (None, value) = kotlin_argument(*argument, source)
            && value.kind() == "integer_literal"
        {
            build
                .toolchains
                .push((text(value, source).to_owned(), value.byte_range()));
        }
    }
    build.toolchains.sort_by_key(|(_, range)| range.start);
    for declaration in &mut build.declarations {
        if let GradleTarget::Module {
            version: version @ None,
            kotlin_notation: true,
            ..
        } = &mut declaration.target
        {
            version.clone_from(&kotlin_plugin_version);
        }
    }
    Some(build)
}

/// One statement of a `dependencies { }` block.
fn gradle_declaration(statement: Node<'_>, source: &str) -> Result<GradleDeclaration, String> {
    let (configuration, suffix) = kotlin_call(statement, source)
        .ok_or_else(|| "a statement that is not a dependency declaration".to_owned())?;
    let (target, platform) = gradle_target(&kotlin_arguments(suffix), source, true)?;
    Ok(GradleDeclaration {
        configuration,
        range: statement.byte_range(),
        target,
        platform,
    })
}

fn gradle_target(
    arguments: &[Node<'_>],
    source: &str,
    allow_platform: bool,
) -> Result<(GradleTarget, Option<&'static str>), String> {
    let labelled = arguments
        .iter()
        .map(|argument| kotlin_argument(*argument, source))
        .collect::<Vec<_>>();
    if !labelled.is_empty() && labelled.iter().all(|(label, _)| label.is_some()) {
        let field = |name: &str| {
            labelled
                .iter()
                .find(|(label, _)| label.as_deref() == Some(name))
                .map(|(_, value)| {
                    kotlin_plain_string_literal(*value, source)
                        .map(str::to_owned)
                        .ok_or_else(|| format!("the {name} argument is not a plain string"))
                })
                .transpose()
        };
        let (Some(group), Some(name)) = (field("group")?, field("name")?) else {
            return Err("a named-argument dependency without group and name".to_owned());
        };
        return Ok((
            GradleTarget::Module {
                group,
                name,
                version: field("version")?,
                kotlin_notation: false,
            },
            None,
        ));
    }
    let [(None, value)] = labelled.as_slice() else {
        return Err("a dependency with arguments this reader does not interpret".to_owned());
    };
    if let Some(coordinate) = kotlin_plain_string_literal(*value, source) {
        // `group:name[:version[:classifier]][@extension]` is the literal's
        // value, not source syntax.
        let coordinate = coordinate.split('@').next().unwrap_or(coordinate);
        return match coordinate.split(':').collect::<Vec<_>>().as_slice() {
            [group, name, rest @ ..]
                if !group.is_empty() && !name.is_empty() && rest.len() <= 2 =>
            {
                Ok((
                    GradleTarget::Module {
                        group: (*group).to_owned(),
                        name: (*name).to_owned(),
                        version: rest
                            .first()
                            .filter(|version| !version.is_empty())
                            .map(|version| (*version).to_owned()),
                        kotlin_notation: false,
                    },
                    None,
                ))
            }
            _ => Err(format!(
                "{coordinate:?} is not a group:name:version coordinate"
            )),
        };
    }
    match value.kind() {
        "string_literal" => {
            Err("a coordinate with a template or escape is evaluated by the build".to_owned())
        }
        "navigation_expression" => catalog_accessor(*value, source),
        _ => {
            let Some((callee, inner)) = kotlin_call(*value, source) else {
                return Err("a dependency notation this reader does not interpret".to_owned());
            };
            match (callee.as_str(), kotlin_string_arguments(inner, source)) {
                ("platform" | "enforcedPlatform", _) if allow_platform => {
                    let platform = if callee == "platform" {
                        "platform"
                    } else {
                        "enforcedPlatform"
                    };
                    let (target, _) = gradle_target(&kotlin_arguments(inner), source, false)?;
                    Ok((target, Some(platform)))
                }
                ("project", Some(arguments)) if arguments.len() == 1 => {
                    Ok((GradleTarget::Project(arguments[0].to_owned()), None))
                }
                ("kotlin", Some(arguments)) if matches!(arguments.len(), 1 | 2) => Ok((
                    GradleTarget::Module {
                        group: "org.jetbrains.kotlin".to_owned(),
                        name: format!("kotlin-{}", arguments[0]),
                        version: arguments.get(1).map(|version| (*version).to_owned()),
                        kotlin_notation: true,
                    },
                    None,
                )),
                _ => Err(format!(
                    "a {callee}(...) dependency this reader does not interpret"
                )),
            }
        }
    }
}

/// `libs.commons.text`, the default catalog's accessor for alias
/// `commons-text`, `commons_text` or `commons.text`.
fn catalog_accessor(
    value: Node<'_>,
    source: &str,
) -> Result<(GradleTarget, Option<&'static str>), String> {
    let mut segments = Vec::new();
    let mut node = value;
    loop {
        let children = named_children(node);
        match (node.kind(), children.as_slice()) {
            ("navigation_expression", [receiver, suffix])
                if suffix.kind() == "navigation_suffix" =>
            {
                let name = child_of_kind(*suffix, "simple_identifier")
                    .ok_or_else(|| "a catalog accessor with a computed member".to_owned())?;
                segments.push(kotlin_identifier_text(name, source));
                node = *receiver;
            }
            ("simple_identifier", []) => {
                segments.push(kotlin_identifier_text(node, source));
                break;
            }
            _ => return Err("an accessor this reader does not interpret".to_owned()),
        }
    }
    segments.reverse();
    match segments.as_slice() {
        ["libs", rest @ ..] if !rest.is_empty() => {
            Ok((GradleTarget::Catalog(rest.join(".")), None))
        }
        _ => Err(format!(
            "{} is not an accessor of the default libs catalog",
            segments.join(".")
        )),
    }
}

/// The build definition of one `build.sbt`.
#[derive(Debug, Default)]
pub(crate) struct SbtBuild {
    pub(crate) scala_version: Option<(String, Range<usize>)>,
    /// Explicit `lazy val x = project...` definitions, in source order.
    pub(crate) projects: Vec<SbtProject>,
    /// Settings written at the top level, which apply to the root project.
    pub(crate) root: SbtProject,
    pub(crate) unread: Vec<Unread>,
}

#[derive(Debug, Default)]
pub(crate) struct SbtProject {
    /// The project id: the `lazy val` name.
    pub(crate) id: String,
    /// The base directory relative to the build, as `file(...)` names it.
    pub(crate) directory: String,
    /// Ids of `dependsOn` projects with the scope their configuration maps
    /// to.
    pub(crate) depends_on: Vec<(String, DependencyScope)>,
    pub(crate) dependencies: Vec<SbtDependency>,
}

#[derive(Debug)]
pub(crate) struct SbtDependency {
    pub(crate) group: String,
    pub(crate) artifact: String,
    /// `%%` appends the Scala binary version to the artifact.
    pub(crate) cross_binary: bool,
    pub(crate) version: String,
    pub(crate) configuration: Option<String>,
    pub(crate) range: Range<usize>,
}

fn scala_language() -> tree_sitter::Language {
    brokk_bifrost_jvm::scala::language::LANGUAGE.into()
}

/// The value of a one-line string literal with no escape.
fn scala_plain_string<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let raw = text(node, source);
    if node.kind() != "string" || node.named_child_count() != 0 || raw.starts_with("\"\"\"") {
        return None;
    }
    raw.strip_prefix('"')?.strip_suffix('"')
}

struct SbtReader<'source> {
    source: &'source str,
    /// Top-level `val x = "literal"` definitions, for `% akkaVersion`.
    strings: Vec<(&'source str, &'source str)>,
    unread: Vec<Unread>,
}

impl SbtReader<'_> {
    fn string(&self, node: Node<'_>) -> Option<String> {
        if let Some(value) = scala_plain_string(node, self.source) {
            return Some(value.to_owned());
        }
        if node.kind() != "identifier" {
            return None;
        }
        let name = text(node, self.source);
        self.strings
            .iter()
            .rev()
            .find(|(defined, _)| *defined == name)
            .map(|(_, value)| (*value).to_owned())
    }

    /// `a op b op c ...` flattened from Scala's left-associative infix tree.
    fn infix_chain<'tree>(&self, node: Node<'tree>) -> (Vec<Node<'tree>>, Vec<String>) {
        let mut operands = Vec::new();
        let mut operators = Vec::new();
        let mut node = node;
        while node.kind() == "infix_expression"
            && let (Some(left), Some(operator), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("operator"),
                node.child_by_field_name("right"),
            )
        {
            operands.push(right);
            operators.push(text(operator, self.source).to_owned());
            node = left;
        }
        operands.push(node);
        operands.reverse();
        operators.reverse();
        (operands, operators)
    }

    /// `"g" % "a" % "v"`, `%%` for a cross-built artifact, and an optional
    /// trailing `% Test` or `% "test"`.
    fn dependency(&self, node: Node<'_>) -> Result<SbtDependency, String> {
        let mut expression = node;
        loop {
            // Exclusions and artifact flags do not change the version.
            let flag_receiver = expression
                .child_by_field_name("function")
                .filter(|function| {
                    expression.kind() == "call_expression"
                        && function.kind() == "field_expression"
                        && function.child_by_field_name("field").is_some_and(|field| {
                            matches!(
                                text(field, self.source),
                                "exclude"
                                    | "excludeAll"
                                    | "withSources"
                                    | "withJavadoc"
                                    | "intransitive"
                            )
                        })
                })
                .and_then(|function| function.child_by_field_name("value"));
            if let Some(receiver) = flag_receiver {
                expression = receiver;
            } else if expression.kind() == "parenthesized_expression" {
                expression = named_children(expression)
                    .into_iter()
                    .next()
                    .ok_or_else(|| "an empty parenthesized expression".to_owned())?;
            } else {
                break;
            }
        }
        let (operands, operators) = self.infix_chain(expression);
        let cross_binary = match operators.first().map(String::as_str) {
            Some("%") => false,
            Some("%%") => true,
            Some("%%%") => {
                return Err(
                    "a %%% Scala.js or Native artifact names a platform suffix this reader does not model"
                        .to_owned(),
                );
            }
            _ => return Err("a dependency expression this reader does not interpret".to_owned()),
        };
        if !matches!(operators.len(), 2 | 3) || operators[1..].iter().any(|op| op != "%") {
            return Err("a dependency expression this reader does not interpret".to_owned());
        }
        let value = |index: usize, what: &str| {
            self.string(operands[index])
                .ok_or_else(|| format!("the {what} is not a literal or a literal val"))
        };
        // `% Test` names an sbt configuration object; `% "test"` its name.
        let configuration = match operands.get(3) {
            None => None,
            Some(node) if node.kind() == "identifier" && self.string(*node).is_none() => {
                Some(text(*node, self.source).to_ascii_lowercase())
            }
            Some(_) => Some(value(3, "configuration")?),
        };
        Ok(SbtDependency {
            group: value(0, "organization")?,
            artifact: value(1, "artifact name")?,
            cross_binary,
            version: value(2, "version")?,
            configuration,
            range: node.byte_range(),
        })
    }

    /// One setting expression applied to `project`.
    fn setting(
        &mut self,
        node: Node<'_>,
        project: &mut SbtProject,
        scala_version: &mut Option<(String, Range<usize>)>,
    ) {
        let (Some(left), Some(operator), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("operator"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if node.kind() != "infix_expression" {
            return;
        }
        // `ThisBuild / key` scopes a key to the whole build.
        let key = match left.kind() {
            "identifier" => text(left, self.source),
            "infix_expression" => match left.child_by_field_name("right") {
                Some(key) if key.kind() == "identifier" => text(key, self.source),
                _ => return,
            },
            _ => return,
        };
        match (key, text(operator, self.source)) {
            ("scalaVersion", ":=") => match self.string(right) {
                Some(version) => *scala_version = Some((version, right.byte_range())),
                None => self.unread.push((
                    node.byte_range(),
                    "scalaVersion is not a literal".to_owned(),
                )),
            },
            ("libraryDependencies", "+=") => match self.dependency(right) {
                Ok(dependency) => project.dependencies.push(dependency),
                Err(reason) => self.unread.push((right.byte_range(), reason)),
            },
            ("libraryDependencies", "++=") => {
                let elements = (right.kind() == "call_expression"
                    && right
                        .child_by_field_name("function")
                        .is_some_and(|function| text(function, self.source) == "Seq"))
                .then(|| right.child_by_field_name("arguments"))
                .flatten()
                .map(named_children);
                match elements {
                    Some(elements) => {
                        for element in elements {
                            match self.dependency(element) {
                                Ok(dependency) => project.dependencies.push(dependency),
                                Err(reason) => self.unread.push((element.byte_range(), reason)),
                            }
                        }
                    }
                    None => self.unread.push((
                        right.byte_range(),
                        "libraryDependencies ++= a value that is not a literal Seq".to_owned(),
                    )),
                }
            }
            ("libraryDependencies", _) => self.unread.push((
                node.byte_range(),
                "libraryDependencies is assigned in a way this reader does not interpret"
                    .to_owned(),
            )),
            _ => {}
        }
    }

    /// `(project in file("dir")).settings(...).dependsOn(...)` and
    /// `project.in(file("dir"))`, unwound from the outermost call. `None`
    /// when `value` does not define a project.
    fn project(
        &mut self,
        id: &str,
        value: Node<'_>,
        scala_version: &mut Option<(String, Range<usize>)>,
    ) -> Option<SbtProject> {
        let mut calls = Vec::new();
        let mut node = value;
        let mut base = loop {
            match node.kind() {
                "call_expression" => {
                    let function = node.child_by_field_name("function")?;
                    let arguments = node.child_by_field_name("arguments")?;
                    if function.kind() != "field_expression" {
                        return None;
                    }
                    calls.push((
                        text(function.child_by_field_name("field")?, self.source),
                        arguments,
                    ));
                    node = function.child_by_field_name("value")?;
                }
                "parenthesized_expression" => node = named_children(node).into_iter().next()?,
                "infix_expression" => {
                    let left = node.child_by_field_name("left")?;
                    let operator = node.child_by_field_name("operator")?;
                    if text(left, self.source) != "project" || text(operator, self.source) != "in" {
                        return None;
                    }
                    break node.child_by_field_name("right");
                }
                "identifier" if text(node, self.source) == "project" => break None,
                _ => return None,
            }
        };
        let mut project = SbtProject {
            id: id.to_owned(),
            directory: id.to_owned(),
            ..SbtProject::default()
        };
        for (method, arguments) in calls.into_iter().rev() {
            let arguments = named_children(arguments);
            match method {
                "in" => base = arguments.first().copied(),
                "settings" => {
                    for setting in arguments {
                        self.setting(setting, &mut project, scala_version);
                    }
                }
                "dependsOn" => {
                    for dependency in arguments {
                        let (target, scope) = match dependency.kind() {
                            "identifier" => (dependency, DependencyScope::Compile),
                            // `core % "test->test"` maps configurations.
                            "infix_expression" => {
                                let mapping = dependency
                                    .child_by_field_name("right")
                                    .and_then(|right| scala_plain_string(right, self.source));
                                let scope = match mapping {
                                    Some(mapping) if mapping.starts_with("test") => {
                                        DependencyScope::Test
                                    }
                                    Some(mapping) if mapping.starts_with("compile") => {
                                        DependencyScope::Compile
                                    }
                                    _ => DependencyScope::Unknown,
                                };
                                match dependency.child_by_field_name("left") {
                                    Some(left) if left.kind() == "identifier" => (left, scope),
                                    _ => continue,
                                }
                            }
                            _ => continue,
                        };
                        project
                            .depends_on
                            .push((text(target, self.source).to_owned(), scope));
                    }
                }
                _ => {}
            }
        }
        if let Some(base) = base {
            let directory = (base.kind() == "call_expression"
                && base
                    .child_by_field_name("function")
                    .is_some_and(|function| text(function, self.source) == "file"))
            .then(|| base.child_by_field_name("arguments"))
            .flatten()
            .and_then(|arguments| match named_children(arguments).as_slice() {
                [path] => scala_plain_string(*path, self.source).map(str::to_owned),
                _ => None,
            });
            match directory {
                Some(directory) => project.directory = directory,
                None => {
                    self.unread.push((
                        base.byte_range(),
                        format!("the base directory of {id} is not a literal file(...)"),
                    ));
                    return None;
                }
            }
        }
        Some(project)
    }
}

pub(crate) fn read_sbt_build(source: &str) -> Option<SbtBuild> {
    let tree = parse(scala_language(), source)?;
    let statements = named_children(tree.root_node());
    let mut reader = SbtReader {
        source,
        strings: Vec::new(),
        unread: Vec::new(),
    };
    for statement in &statements {
        if statement.kind() == "val_definition"
            && let (Some(pattern), Some(value)) = (
                statement.child_by_field_name("pattern"),
                statement.child_by_field_name("value"),
            )
            && pattern.kind() == "identifier"
            && let Some(literal) = scala_plain_string(value, source)
        {
            reader.strings.push((text(pattern, source), literal));
        }
    }
    let mut build = SbtBuild {
        root: SbtProject {
            directory: ".".to_owned(),
            ..SbtProject::default()
        },
        ..SbtBuild::default()
    };
    for statement in statements {
        match statement.kind() {
            "val_definition" => {
                let (Some(pattern), Some(value)) = (
                    statement.child_by_field_name("pattern"),
                    statement.child_by_field_name("value"),
                ) else {
                    continue;
                };
                if pattern.kind() != "identifier" {
                    continue;
                }
                if let Some(project) =
                    reader.project(text(pattern, source), value, &mut build.scala_version)
                {
                    build.projects.push(project);
                }
            }
            "infix_expression" => {
                reader.setting(statement, &mut build.root, &mut build.scala_version);
            }
            _ => {}
        }
    }
    build.unread = reader.unread;
    Some(build)
}

/// The Scala binary version `%%` appends: `2.13` for `2.13.16`, `3` for
/// any Scala 3 release.
pub(crate) fn scala_binary_version(version: &str) -> Option<String> {
    let mut parts = version.split('.');
    match (parts.next()?, parts.next()) {
        ("3", _) => Some("3".to_owned()),
        (major, Some(minor)) if !major.is_empty() && major.chars().all(|c| c.is_ascii_digit()) => {
            Some(format!("{major}.{minor}"))
        }
        _ => None,
    }
}
