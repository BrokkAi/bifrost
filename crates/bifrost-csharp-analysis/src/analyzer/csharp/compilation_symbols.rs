//! Snapshot-only MSBuild property evaluation for selected C# symbols.
use super::*;
use brokk_bifrost_analysis::analyzer::store::csharp_compilation::CSharpSymbolEnvironment;
use std::sync::Arc;

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
            Operation::Property(name, PropertyValue { value, conditions })
                if name.eq_ignore_ascii_case("targetframeworks") && conditions.is_empty() =>
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
                        let value = value
                            .unconditional()
                            .and_then(|value| expand(&value, &properties));
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
                Operation::Import(_) | Operation::ConfigurationName(_) => {}
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
        ("configurations", "Debug;Release"),
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
            // dotnet/sdk d037e5f857b3
            // Microsoft.NET.DefaultOutputPaths.targets:145-147 only appends the
            // framework when AppendTargetFrameworkToOutputPath is true.
            if let Some(append) = properties.get("appendtargetframeworktooutputpath") {
                let append = append.as_ref().map_err(|_| "dynamic_property")?;
                if append.eq_ignore_ascii_case("false") {
                    return Ok(value);
                }
                if !append.is_empty() && !append.eq_ignore_ascii_case("true") {
                    return Err("dynamic_property");
                }
            }
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

/// The membership property pass (#7314 AD3d). MSBuild evaluates property
/// groups and their conditions in import order, and a condition sees each
/// property's value at that point; a later assignment never reruns an earlier
/// condition.
///
/// A property assigned anywhere in the project's in-tree chain is empty until
/// its first executed assignment, so a condition that reads it earlier is
/// decided. `MSBuildProjectName` carries its exact value. Every other property
/// is unknown, and a condition that reads it stays an obligation. That includes
/// SDK-defaulted properties, whose assignment point relative to the workspace's
/// files is not modeled here. Command-line and environment values are the
/// single residual risk stated in name-resolution.md, "Workspace context".
///
/// The chain places an explicitly imported file ahead of the whole file that
/// imports it, so the order between an importer's own assignments and its
/// imports is not exact. Every property an importer assigns is therefore
/// unknown, and no condition inside an importer is decided.
pub(super) struct OrderedProperties {
    state: Properties,
    globals: HashSet<String>,
    // Census properties still empty only because nothing assigned them yet.
    seeded: HashSet<String>,
    order_ambiguous: HashSet<String>,
    // A fragment the scalar evaluator cannot read may assign anything.
    poisoned: bool,
}

impl OrderedProperties {
    pub(super) fn new<'a>(
        chain_sources: impl Iterator<Item = &'a str>,
        project_name: &str,
        global_properties: &[(&str, &str)],
    ) -> Self {
        let mut state = Properties::default();
        let mut seeded = HashSet::default();
        let mut order_ambiguous = HashSet::default();
        let mut poisoned = false;
        for source in chain_sources {
            let Ok(operations) = operations(source) else {
                poisoned = true;
                continue;
            };
            let imports = operations
                .iter()
                .any(|operation| matches!(operation, Operation::Import(_)));
            for operation in operations {
                if let Operation::Property(name, _) = operation {
                    if imports {
                        order_ambiguous.insert(name.clone());
                    }
                    if !sdk_or_reserved_property(&name) {
                        state.insert(name.clone(), Ok(String::new()));
                        seeded.insert(name);
                    }
                }
            }
        }
        for name in &order_ambiguous {
            seeded.remove(name);
            state.insert(name.clone(), Err("import_order"));
        }
        state.insert("msbuildprojectname".into(), Ok(project_name.to_owned()));
        let mut globals = HashSet::default();
        for &(name, value) in global_properties {
            let name = name.to_ascii_lowercase();
            seeded.remove(&name);
            order_ambiguous.remove(&name);
            state.insert(name.clone(), Ok(value.to_owned()));
            globals.insert(name);
        }
        Self {
            state,
            globals,
            seeded,
            order_ambiguous,
            poisoned,
        }
    }

    /// Past the `Directory.Build.props` closure, SDK, package and project props
    /// may assign any property, so a census property still unassigned there is
    /// no longer known to be empty.
    pub(super) fn leave_props_phase(&mut self) {
        for name in self.seeded.drain() {
            self.state.insert(name, Err("unassigned_after_props"));
        }
    }

    /// A chain fragment without readable source may assign anything.
    pub(super) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Execute one fragment's property operations in document order.
    pub(super) fn apply(&mut self, source: &str) {
        let Ok(operations) = operations(source) else {
            self.poisoned = true;
            return;
        };
        // MSBuild decides a PropertyGroup's condition once, on entry. Sibling
        // properties share that condition's text, so its first decision holds
        // for the whole group even if a sibling changes a property it reads.
        let mut entered = EnteredConditions::default();
        for operation in operations {
            match operation {
                Operation::Property(name, PropertyValue { value, conditions }) => {
                    if self.globals.contains(&name) {
                        continue;
                    }
                    let decision = self.decide_with(&conditions, |condition| {
                        entered.decide(condition, &self.state)
                    });
                    let value = match decision {
                        Some(false) => continue,
                        _ if self.order_ambiguous.contains(&name) => Err("import_order"),
                        // The SDK can reassign its own properties after this point.
                        _ if sdk_or_reserved_property(&name) => Err("sdk_property"),
                        Some(true) => expand(&value, &self.state),
                        None => Err("condition"),
                    };
                    self.seeded.remove(&name);
                    self.state.insert(name, value);
                }
                Operation::TargetProperty(name) => {
                    if !self.globals.contains(&name) {
                        self.state.insert(name, Err("target_assignment"));
                    }
                }
                Operation::TreatAsLocalProperty if !self.globals.is_empty() => {
                    self.poisoned = true;
                }
                Operation::TreatAsLocalProperty
                | Operation::Import(_)
                | Operation::ConfigurationName(_) => {}
            }
        }
    }

    /// Decide an assignment's nested conditions at the start of its fragment.
    /// The caller has not applied that fragment yet, so a condition reading a
    /// property the fragment itself assigns is undecided: its value at the
    /// assignment may differ from the value at the fragment's start.
    pub(super) fn decide_at_fragment_start(
        &self,
        conditions: &[Arc<str>],
        fragment: &str,
    ) -> Option<bool> {
        if conditions.is_empty() {
            return Some(true);
        }
        let operations = operations(fragment).ok()?;
        if operations
            .iter()
            .any(|operation| matches!(operation, Operation::Import(_)))
        {
            return None;
        }
        let assigned = operations
            .into_iter()
            .filter_map(|operation| match operation {
                Operation::Property(name, _) | Operation::TargetProperty(name) => {
                    (!self.globals.contains(&name)).then_some(name)
                }
                Operation::TreatAsLocalProperty
                | Operation::Import(_)
                | Operation::ConfigurationName(_) => None,
            })
            .collect::<HashSet<_>>();
        if conditions
            .iter()
            .any(|condition| referenced_properties(condition).any(|name| assigned.contains(&name)))
        {
            return None;
        }
        self.decide(conditions)
    }

    /// Item conditions see the final property state.
    pub(super) fn decide_final(&self, conditions: &[Arc<str>]) -> Option<bool> {
        self.decide(conditions)
    }

    /// Item paths see the final property state.
    pub(super) fn expand_final(&self, value: &str) -> Result<String, &'static str> {
        if self.poisoned {
            return Err("unknown_fragment");
        }
        expand(value, &self.state)
    }

    fn decide(&self, conditions: &[Arc<str>]) -> Option<bool> {
        self.decide_with(conditions, |condition| {
            evaluate_condition(condition, &self.state)
        })
    }

    // Nested conditions all guard one assignment: any definite false skips it.
    fn decide_with(
        &self,
        conditions: &[Arc<str>],
        evaluate: impl FnMut(&Arc<str>) -> Option<bool>,
    ) -> Option<bool> {
        if self.poisoned {
            return None;
        }
        decide_conditions(conditions, evaluate)
    }
}

// Nested conditions guard an assignment using Kleene conjunction.
fn decide_conditions(
    conditions: &[Arc<str>],
    mut evaluate: impl FnMut(&Arc<str>) -> Option<bool>,
) -> Option<bool> {
    let mut decided = Some(true);
    for condition in conditions {
        match evaluate(condition) {
            Some(false) => return Some(false),
            Some(true) => {}
            None => decided = None,
        }
    }
    decided
}

// Group guards retain their entry decision while siblings execute. Keep the
// Arc alive so an imported fragment cannot reuse a previous guard's address.
#[derive(Default)]
struct EnteredConditions {
    decisions: HashMap<*const str, (Arc<str>, Option<bool>)>,
}

impl EnteredConditions {
    fn decide(&mut self, condition: &Arc<str>, properties: &Properties) -> Option<bool> {
        self.decisions
            .entry(Arc::as_ptr(condition))
            .or_insert_with(|| {
                (
                    Arc::clone(condition),
                    evaluate_condition(condition, properties),
                )
            })
            .1
    }
}

// Reserved MSBuild properties and SDK-assigned properties can hold a value
// before a workspace file's first assignment, so none of them starts empty.
fn sdk_or_reserved_property(name: &str) -> bool {
    name.starts_with("msbuild")
        || super::sdk_properties::SDK_ASSIGNED_PROPERTIES
            .binary_search(&name)
            .is_ok()
}

// Property names read through `$(Name)` in one condition, lowercased.
fn referenced_properties(condition: &str) -> impl Iterator<Item = String> + '_ {
    condition.split("$(").skip(1).filter_map(|tail| {
        tail.find(')')
            .map(|end| tail[..end].trim().to_ascii_lowercase())
    })
}

// Evaluates an MSBuild condition attribute (never C# source) in Kleene
// three-valued logic over its whole expression: `==` and `!=` comparisons of
// quoted or bare operands, boolean operands, `!`, parentheses and `and` / `or`
// (`and` binds tighter). An operand the snapshot cannot know is undecided,
// `false and x` is false and `true or x` is true for every x, and `!` of an
// undecided value is undecided. Function calls such as `Exists(...)` and
// relational comparisons are undecided leaves. Malformed text is undecided as a
// whole. Newtonsoft.Json's library reads
// `'$(MSBuildProjectName)'=='Newtonsoft.Json.Tests' and '$(TestLibraryFramework)'!=''`
// with the second property never assigned, so the first operand decides it.
#[derive(Clone, Copy)]
enum Token<'a> {
    Quoted(&'a str),
    Bare(&'a str),
    Unknown,
    Open,
    Close,
    Not,
    Equal,
    NotEqual,
    Relational,
    And,
    Or,
}
// The byte index just past the parenthesis that closes the one at `open`,
// skipping quoted text.
fn closing(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quoted = false;
    for (index, ch) in text[open..].char_indices() {
        match ch {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + index + 1);
                }
            }
            _ => {}
        }
    }
    None
}
fn condition_tokens(condition: &str) -> Option<Vec<Token<'_>>> {
    let mut tokens = Vec::new();
    let mut rest = condition.trim_start();
    while !rest.is_empty() {
        let (token, after) = if let Some(after) = rest.strip_prefix('\'') {
            let end = after.find('\'')?;
            (Token::Quoted(&after[..end]), &after[end + 1..])
        } else if let Some(after) = rest.strip_prefix("==") {
            (Token::Equal, after)
        } else if let Some(after) = rest.strip_prefix("!=") {
            (Token::NotEqual, after)
        } else if let Some(after) = ["<=", ">=", "<", ">"]
            .iter()
            .find_map(|operator| rest.strip_prefix(operator))
        {
            (Token::Relational, after)
        } else if let Some(after) = rest.strip_prefix('!') {
            (Token::Not, after)
        } else if let Some(after) = rest.strip_prefix('(') {
            (Token::Open, after)
        } else if let Some(after) = rest.strip_prefix(')') {
            (Token::Close, after)
        } else if rest.starts_with("$(") {
            let end = closing(rest, 1)?;
            (Token::Bare(&rest[..end]), &rest[end..])
        } else {
            let end = rest
                .find(|ch: char| ch.is_whitespace() || "'()!=<>".contains(ch))
                .unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            let word = &rest[..end];
            if word.eq_ignore_ascii_case("and") {
                (Token::And, &rest[end..])
            } else if word.eq_ignore_ascii_case("or") {
                (Token::Or, &rest[end..])
            } else if rest[end..].starts_with('(') {
                // A function call such as Exists('...') or HasTrailingSlash('...').
                let close = closing(rest, end)?;
                (Token::Unknown, &rest[close..])
            } else {
                (Token::Bare(word), &rest[end..])
            }
        };
        tokens.push(token);
        rest = after.trim_start();
    }

    Some(tokens)
}

fn evaluate_condition(condition: &str, properties: &Properties) -> Option<bool> {
    let tokens = condition_tokens(condition)?;
    // Recursive descent over a short attribute value; the depth cap keeps a
    // pathological nesting undecided instead of deep.
    const MAX_DEPTH: usize = 32;
    struct Parser<'t, 'a> {
        tokens: &'t [Token<'a>],
        next: usize,
        properties: &'t Properties,
    }
    impl Parser<'_, '_> {
        fn peek(&self) -> Option<Token<'_>> {
            self.tokens.get(self.next).copied()
        }
        // The outer Option is None for malformed text; the inner one is the
        // three-valued result.
        fn or(&mut self, depth: usize) -> Option<Option<bool>> {
            let mut value = self.and(depth)?;
            while matches!(self.peek(), Some(Token::Or)) {
                self.next += 1;
                let right = self.and(depth)?;
                value = match (value, right) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                };
            }
            Some(value)
        }
        fn and(&mut self, depth: usize) -> Option<Option<bool>> {
            let mut value = self.unary(depth)?;
            while matches!(self.peek(), Some(Token::And)) {
                self.next += 1;
                let right = self.unary(depth)?;
                value = match (value, right) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                };
            }
            Some(value)
        }
        fn unary(&mut self, depth: usize) -> Option<Option<bool>> {
            if depth > MAX_DEPTH {
                return None;
            }
            match self.peek()? {
                Token::Not => {
                    self.next += 1;
                    Some(self.unary(depth + 1)?.map(|value| !value))
                }
                Token::Open => {
                    self.next += 1;
                    let value = self.or(depth + 1)?;
                    if !matches!(self.peek(), Some(Token::Close)) {
                        return None;
                    }
                    self.next += 1;
                    Some(value)
                }
                Token::Quoted(_) | Token::Bare(_) | Token::Unknown => self.comparison(),
                Token::Close
                | Token::Equal
                | Token::NotEqual
                | Token::Relational
                | Token::And
                | Token::Or => None,
            }
        }
        fn operand(&self, token: Token<'_>) -> Option<Result<String, &'static str>> {
            match token {
                Token::Quoted(text) => Some(expand(text, self.properties)),
                Token::Bare(text) if text.starts_with("$(") => Some(expand(text, self.properties)),
                Token::Bare(text) => Some(Ok(text.to_string())),
                Token::Unknown => Some(Err("condition_function")),
                _ => None,
            }
        }
        fn comparison(&mut self) -> Option<Option<bool>> {
            let left = self.operand(self.peek()?)?;
            self.next += 1;
            let negated = match self.peek() {
                Some(Token::Equal) => false,
                Some(Token::NotEqual) => true,
                Some(Token::Relational) => {
                    self.next += 1;
                    // Relational comparisons are undecided; only the operand's
                    // presence is checked.
                    if !matches!(
                        self.peek(),
                        Some(Token::Quoted(_) | Token::Bare(_) | Token::Unknown)
                    ) {
                        return None;
                    }
                    self.next += 1;
                    return Some(None);
                }
                // A lone operand is a boolean: 'true', 'off', '!yes' and so on.
                _ => return Some(left.ok().and_then(|value| msbuild_boolean(&value))),
            };
            self.next += 1;
            let right = self.operand(self.peek()?)?;
            self.next += 1;
            Some(match (left, right) {
                (Ok(left), Ok(right)) => msbuild_equal(&left, &right).map(|equal| equal != negated),
                _ => None,
            })
        }
    }
    let mut parser = Parser {
        tokens: &tokens,
        next: 0,
        properties,
    };
    let value = parser.or(0)?;
    (parser.next == tokens.len()).then_some(value).flatten()
}

// MSBuild compares two numbers numerically and two boolean literals as
// booleans before falling back to strings, so '01' equals '1' and 'on' equals
// 'true'. Equal spellings are equal in every mode; two booleans compare by
// value; differing spellings of two numbers stay undecided.
fn msbuild_equal(left: &str, right: &str) -> Option<bool> {
    if left.eq_ignore_ascii_case(right) {
        Some(true)
    } else if let (Some(left), Some(right)) = (msbuild_boolean(left), msbuild_boolean(right)) {
        Some(left == right)
    } else if msbuild_number(left) && msbuild_number(right) {
        None
    } else {
        Some(false)
    }
}

// Over-approximates MSBuild's numeric operands (decimal and 0x hexadecimal),
// so a comparison it might treat numerically stays undecided.
fn msbuild_number(value: &str) -> bool {
    let value = value.trim();
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    hex || value.parse::<f64>().is_ok()
}

// MSBuild's boolean literals and their negations.
fn msbuild_boolean(value: &str) -> Option<bool> {
    let value = value.trim();
    let (negated, literal) = match value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let truth = if ["true", "on", "yes"]
        .iter()
        .any(|word| literal.eq_ignore_ascii_case(word))
    {
        true
    } else if ["false", "off", "no"]
        .iter()
        .any(|word| literal.eq_ignore_ascii_case(word))
    {
        false
    } else {
        return None;
    };
    Some(truth != negated)
}

fn initial_properties() -> Properties {
    [
        ("configuration", "Debug"),
        ("configurations", "Debug;Release"),
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
    Property(String, PropertyValue),
    TargetProperty(String),
    TreatAsLocalProperty,
    ConfigurationName(Result<String, &'static str>),
    Import(Result<String, &'static str>),
}
// Keep the inherited expressions until the consumer chooses its evaluation
// semantics. Symbol selection deliberately retains its existing conservative
// handling; membership can execute these expressions in the property pass.
#[derive(Debug)]
struct PropertyValue {
    value: String,
    // Share condition text across sibling operations: a large group condition
    // must not be copied once per property within the bounded XML document.
    conditions: Vec<Arc<str>>,
}

impl PropertyValue {
    fn unconditional(self) -> Result<String, &'static str> {
        if self.conditions.is_empty() {
            Ok(self.value)
        } else {
            Err("condition")
        }
    }
}

fn operations(source: &str) -> Result<Vec<Operation>, &'static str> {
    let mut reader = Reader::from_str(source);
    let mut stack: Vec<(String, Vec<Arc<str>>, String)> = Vec::new();
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
                let mut conditions = stack
                    .last()
                    .map(|frame| frame.1.clone())
                    .unwrap_or_default();
                if stack.last().is_some_and(|frame| frame.0 == "choose") {
                    // Choose/When is outside the supported scalar condition set.
                    conditions.push(Arc::from("Choose"));
                }
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
                        "condition" => {
                            // Reuse the evaluator's tokens from this parsed XML
                            // attribute, including conditions on items and imports.
                            let references = referenced_properties(&value)
                                .filter(|name| {
                                    name == "configuration" || name.starts_with("configuration.")
                                })
                                .count();
                            let mut interpreted = 0;
                            if let Some(tokens) = condition_tokens(&value) {
                                for comparison in tokens.windows(3) {
                                    if let [
                                        Token::Quoted(left) | Token::Bare(left),
                                        Token::Equal | Token::NotEqual,
                                        Token::Quoted(right) | Token::Bare(right),
                                    ] = comparison
                                    {
                                        for (property, literal) in [(left, right), (right, left)] {
                                            if property.eq_ignore_ascii_case("$(Configuration)")
                                                && !literal.contains("$(")
                                            {
                                                interpreted += 1;
                                                result.push(Operation::ConfigurationName(Ok(
                                                    (*literal).to_owned(),
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                            if interpreted < references {
                                // A composite or unsupported operand cannot establish
                                // all possible scalar names. Preserve that uncertainty.
                                result.push(Operation::ConfigurationName(Err("condition")));
                            }
                            conditions.push(Arc::from(value));
                        }
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
                    } else if !conditions.is_empty() {
                        Err("condition")
                    } else {
                        import.ok_or("unevaluated_import")
                    }));
                }
                if matches!(event, Event::Start(_)) {
                    stack.push((name, conditions, String::new()));
                } else if stack.last().is_some_and(|frame| frame.0 == "propertygroup") {
                    if in_target {
                        result.push(Operation::TargetProperty(name.to_ascii_lowercase()));
                    } else {
                        result.push(Operation::Property(
                            name.to_ascii_lowercase(),
                            PropertyValue {
                                value: String::new(),
                                conditions,
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
                let (name, conditions, value) = stack.pop().ok_or("dynamic_property")?;
                if stack.last().is_some_and(|frame| frame.0 == "propertygroup") {
                    if stack.iter().any(|frame| frame.0 == "target") {
                        result.push(Operation::TargetProperty(name.to_ascii_lowercase()));
                    } else {
                        result.push(Operation::Property(
                            name.to_ascii_lowercase(),
                            PropertyValue { value, conditions },
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
    inputs: &ConfigurationByPath<'a>,
    project: &str,
    name: &str,
) -> Result<Option<&'a str>, &'static str> {
    let directory = Path::new(project).parent().expect("project parent");
    match super::nearest_configuration(inputs, directory, name) {
        super::NearestConfiguration::Found(path) => Ok(Some(path)),
        super::NearestConfiguration::Absent => Ok(None),
        super::NearestConfiguration::Unknown(_) => Err("unknown_configuration_presence"),
    }
}

// The framework identity and MSBuild globals are separate: only cross-targeting
// inner builds receive TargetFramework as a global before Directory.Build.props.
pub(super) struct FrameworkInstance {
    pub name: String,
    global_properties: Vec<(&'static str, String)>,
}

fn evaluate(
    inputs: &ConfigurationByPath<'_>,
    paths: &[&str],
    properties: &mut Properties,
    configurations: &mut BTreeSet<String>,
    globals: &[(&str, String)],
) -> Result<(), &'static str> {
    let mut entered = EnteredConditions::default();
    evaluate_properties(
        inputs,
        paths,
        properties,
        configurations,
        globals,
        |conditions, properties| {
            decide_conditions(conditions, |condition| {
                entered.decide(condition, properties)
            })
        },
    )?
    .map_or(Ok(()), Err)
}

fn evaluate_properties(
    inputs: &ConfigurationByPath<'_>,
    paths: &[&str],
    properties: &mut Properties,
    configurations: &mut BTreeSet<String>,
    globals: &[(&str, String)],
    mut decide: impl FnMut(&[Arc<str>], &Properties) -> Option<bool>,
) -> Result<Option<&'static str>, &'static str> {
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
                    if globals
                        .iter()
                        .any(|(global, _)| name.eq_ignore_ascii_case(global))
                    {
                        continue;
                    }
                    if name == "configuration" {
                        // A project-authored default is a possible configuration,
                        // even though no selected configuration is assumed here.
                        match expand(&value.value, properties) {
                            Ok(name) => {
                                configurations.insert(name);
                            }
                            Err(reason) => {
                                open_reason.get_or_insert(reason);
                            }
                        }
                        continue;
                    } // Selected global property.
                    if matches!(properties.get(&name), Some(Err("target_assignment"))) {
                        continue;
                    }
                    let condition = decide(&value.conditions, properties);
                    if condition == Some(false) {
                        continue;
                    }
                    let value = if condition == Some(true) {
                        expand(&value.value, properties)
                    } else {
                        Err("condition")
                    };
                    // Conditions remain unknown even if a later assignment
                    // happens to overwrite the same property.
                    if let Err(reason) = &value {
                        open_reason.get_or_insert(*reason);
                    }
                    properties.insert(name, value);
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
                Operation::ConfigurationName(name) => match name {
                    Ok(name) => {
                        configurations.insert(name);
                    }
                    Err(reason) => {
                        open_reason.get_or_insert(reason);
                    }
                },
                Operation::TreatAsLocalProperty if !globals.is_empty() => {
                    return Err("treat_as_local_property");
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
                .get(path.as_str())
                .and_then(|input| input.source.as_deref())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .ok_or("unevaluated_import")?;
            for operation in operations(source)?.into_iter().rev() {
                work.push((path.clone(), depth, Some(operation)));
            }
        }
    }
    Ok(open_reason)
}

fn project_paths<'a>(
    inputs: &ConfigurationByPath<'a>,
    project: &'a str,
) -> Result<Vec<&'a str>, &'static str> {
    let mut paths = Vec::new();
    if let Some(path) = nearest(inputs, project, "Directory.Build.props")? {
        paths.push(path);
    }
    if let Some(path) = nearest(inputs, project, "Directory.Packages.props")? {
        paths.push(path);
    }
    paths.push(project);
    if let Some(path) = nearest(inputs, project, "Directory.Build.targets")? {
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
pub(super) fn derive(
    inputs: &[CSharpConfigurationInput],
    project: Option<&str>,
    framework: &str,
) -> CSharpSymbolEnvironment {
    let by_path = configuration_by_path(inputs);
    let instance = FrameworkInstance {
        name: framework.to_owned(),
        global_properties: Vec::new(),
    };
    derive_indexed(&by_path, project, Some(&instance))
}

pub(super) fn framework_instances(
    inputs: &ConfigurationByPath<'_>,
    project: &str,
) -> Vec<FrameworkInstance> {
    let mut properties = initial_properties();
    properties.insert("targetframework".into(), Ok(String::new()));
    properties.insert("configuration".into(), Err("dynamic_property"));
    let Ok(paths) = project_paths(inputs, project) else {
        return Vec::new();
    };
    let mut entered = EnteredConditions::default();
    // An unknown unrelated property's value does not stop traversal. An import
    // failure does: its unseen assignments can change the framework list.
    if evaluate_properties(
        inputs,
        &paths,
        &mut properties,
        &mut BTreeSet::new(),
        &[],
        |conditions, properties| {
            decide_conditions(conditions, |condition| {
                entered.decide(condition, properties)
            })
        },
    )
    .is_err()
    {
        return Vec::new();
    }
    let cross_targeting = properties
        .get("targetframework")
        .is_some_and(|value| value.as_ref().is_ok_and(|value| value.trim().is_empty()));
    declared_frameworks(&Ok(properties))
        .into_iter()
        .map(|name| {
            let global_properties = if cross_targeting {
                vec![("TargetFramework", name.clone())]
            } else {
                Vec::new()
            };
            FrameworkInstance {
                name,
                global_properties,
            }
        })
        .collect()
}

pub(super) fn declared_frameworks(properties: &Result<Properties, &'static str>) -> Vec<String> {
    properties
        .as_ref()
        .ok()
        .and_then(|properties| {
            properties
                .get("targetframework")
                .filter(|value| !value.as_ref().is_ok_and(|value| value.trim().is_empty()))
                .or_else(|| properties.get("targetframeworks"))
        })
        .and_then(|value| value.as_ref().ok())
        .map(|value| {
            let mut seen = HashSet::default();
            value
                .split(';')
                .map(str::trim)
                .filter(|value| !value.is_empty() && seen.insert(*value))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn derive_indexed(
    inputs: &ConfigurationByPath<'_>,
    project: Option<&str>,
    instance: Option<&FrameworkInstance>,
) -> CSharpSymbolEnvironment {
    let mut environment = CSharpSymbolEnvironment::default();
    let Some(project) = project else {
        return environment;
    };
    let mut properties = initial_properties();
    properties.insert("targetframework".into(), Ok(String::new()));
    let globals = instance
        .map(|instance| instance.global_properties.as_slice())
        .unwrap_or(&[]);
    for (name, value) in globals {
        properties.insert(name.to_ascii_lowercase(), Ok(value.clone()));
    }
    environment.target_framework = instance.map(|instance| instance.name.clone());
    // Configuration is not an instance dimension. A value or alias expanded
    // from it cannot become a definitely defined symbol from a seeded Debug.
    properties.insert("configuration".into(), Err("dynamic_property"));
    let mut configuration_names = BTreeSet::new();
    let result = (|| {
        let source = inputs
            .get(project)
            .and_then(|input| input.source.as_deref())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or("dynamic_property")?;
        let parsed = parse_project(source);
        if parsed.sdks != ["Microsoft.NET.Sdk"] {
            return Err("unevaluated_import");
        }
        let mut property_reason = None;
        if let Some(props) = nearest(inputs, project, "Directory.Build.props")? {
            property_reason = evaluate(
                inputs,
                &[props],
                &mut properties,
                &mut configuration_names,
                globals,
            )
            .err();
        }
        if let Some(packages) = nearest(inputs, project, "Directory.Packages.props")?
            && let Err(reason) = evaluate(
                inputs,
                &[packages],
                &mut properties,
                &mut configuration_names,
                globals,
            )
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
        if let Some(targets) = nearest(inputs, project, "Directory.Build.targets")? {
            body.push(targets);
        }
        if let Err(reason) = evaluate(
            inputs,
            &body,
            &mut properties,
            &mut configuration_names,
            globals,
        ) {
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
            .get(assets_path.as_str())
            .and_then(|input| input.source.as_deref())
            .filter(|source| !source.is_empty())
            .ok_or("unrestored")?;
        let assets: serde_json::Value = serde_json::from_slice(assets).map_err(|_| "unrestored")?;
        // SDK 10.0.403 restore writes this array in sorted order, including
        // when TargetFrameworks was declared in the opposite order (oracle).
        let frameworks = assets
            .pointer("/project/restore/originalTargetFrameworks")
            .and_then(serde_json::Value::as_array)
            .ok_or("unrestored")?;
        // Restore metadata validates an enumerated instance; it cannot select
        // an instance when project enumeration was incomplete.
        let framework = instance
            .map(|instance| instance.name.as_str())
            .ok_or(property_reason.unwrap_or("dynamic_property"))?;
        let framework = Some(framework)
            .filter(|framework| {
                frameworks
                    .iter()
                    .any(|entry| entry.as_str() == Some(*framework))
            })
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
                .get(path.as_str())
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
        let evaluated = properties
            .get("targetframework")
            .expect("initial framework")
            .as_ref()
            .map_err(|reason| *reason)?;
        if evaluated.trim() != framework {
            return Err("dynamic_property");
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
        if !properties
            .get("disableimplicitframeworkdefines")
            .expect("default implicit")
            .as_ref()
            .map_err(|reason| *reason)?
            .eq_ignore_ascii_case("true")
        {
            for symbol in implicit_symbols(framework)? {
                symbols.insert(symbol, "sdk".to_owned());
            }
        }
        // dotnet/sdk d037e5f857b35e7260f575ae026ef30511776c0f:
        // Microsoft.NET.Sdk.CSharp.targets:15-28 uppercases Configuration and
        // replaces '-', '.', and spaces with '_', unless implicit defines are disabled.
        // Configuration is not an instance dimension. Solution mappings are not
        // read here; command-line-only /p:Configuration is outside workspace context.
        if !properties
            .get("disableimplicitconfigurationdefines")
            .expect("configuration default")
            .as_ref()
            .map_err(|reason| *reason)?
            .eq_ignore_ascii_case("true")
        {
            configuration_names.extend(["Debug".to_owned(), "Release".to_owned()]);
            configuration_names.extend(
                properties
                    .get("configurations")
                    .expect("configuration names default")
                    .as_ref()
                    .map_err(|reason| *reason)?
                    .split(';')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned),
            );
            for name in configuration_names.iter().filter(|name| !name.is_empty()) {
                let symbol = name.to_uppercase().replace(['-', '.', ' '], "_");
                if !symbols.contains_key(&symbol) {
                    environment.named_open.push(symbol);
                }
            }
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
        environment.named_open.sort_unstable();
        environment.named_open.dedup();
        environment.symbols = symbols.into_iter().collect();
        Ok(())
    })();
    environment.open_reason = result.err().map(str::to_owned);
    if environment.open_reason.is_some() {
        environment.named_open.clear();
    }
    environment
}

// dotnet/sdk d037e5f857b35e7260f575ae026ef30511776c0f:
// src/Tasks/Microsoft.NET.Build.Tasks/targets/Microsoft.NET.Sdk.BeforeCommon.targets
// :188-207 generates
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
            source: if input.file_present {
                super::csharp_compilation::CSharpConfigurationSource::Bytes(
                    input.source_bytes().into(),
                )
            } else {
                super::csharp_compilation::CSharpConfigurationSource::Absent
            },
        })
        .collect::<Vec<_>>();
    let by_path = configuration_by_path(&configuration);
    let mut paths = Vec::new();
    for file in inputs
        .iter()
        .filter(|input| has_extension(Path::new(input.relative_path()), "csproj"))
    {
        let path = file.relative_path();
        let mut properties = initial_properties();
        let evaluation_open = project_paths(&by_path, path)
            .and_then(|paths| {
                evaluate_properties(
                    &by_path,
                    &paths,
                    &mut properties,
                    &mut BTreeSet::new(),
                    &[],
                    |conditions, _| conditions.is_empty().then_some(true),
                )
                .and_then(|reason| reason.map_or(Ok(()), Err))
            })
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

#[cfg(test)]
mod ordered_global_tests {
    use super::*;

    #[test]
    fn global_framework_survives_assignments_and_props_boundary() {
        let source = r#"<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework><Selected Condition="'$(TargetFramework)' == 'net8.0'">yes</Selected></PropertyGroup><Target Name="Change"><PropertyGroup><TargetFramework>net7.0</TargetFramework></PropertyGroup></Target></Project>"#;
        let mut properties = OrderedProperties::new(
            [source].into_iter(),
            "Example",
            &[("TargetFramework", "net8.0")],
        );
        properties.leave_props_phase();
        properties.apply(source);
        assert_eq!(
            properties.expand_final("$(TargetFramework)"),
            Ok("net8.0".into())
        );
        assert_eq!(properties.expand_final("$(Selected)"), Ok("yes".into()));
        assert_eq!(
            properties.decide_at_fragment_start(
                &[Arc::from("'$(TargetFramework)' == 'net8.0'")],
                source,
            ),
            Some(true),
        );
        properties.apply(r#"<Project TreatAsLocalProperty="TargetFramework" />"#);
        assert_eq!(
            properties.expand_final("$(TargetFramework)"),
            Err("unknown_fragment")
        );
    }
}
