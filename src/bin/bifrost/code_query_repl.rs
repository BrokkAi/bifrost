use brokk_bifrost::analyzer::structural::kinds::{ALL_KINDS, ALL_ROLES, Role};
use brokk_bifrost::analyzer::structural::query::schema::ALL_RQL_FORMS;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryMatch, CodeQueryResult, Pattern, StringPredicate,
};
use brokk_bifrost::{Language, SearchToolsService};
use nu_ansi_term::{Color, Style};
use reedline::{
    ColumnarMenu, Completer, DefaultHinter, DefaultPrompt, Emacs, FileBackedHistory, Highlighter,
    KeyCode, KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
    Span as ReedlineSpan, StyledText, Suggestion, ValidationResult, Validator,
    default_emacs_keybindings,
};
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

const COMMANDS: &[MetadataEntry] = &[
    MetadataEntry::new(":help", "Show commands and S-expression examples."),
    MetadataEntry::new(
        ":doc",
        "Show documentation for a command, kind, role, wrapper, or example.",
    ),
    MetadataEntry::new(":examples", "List named example queries."),
    MetadataEntry::new(":example", "Load a named example into the current query."),
    MetadataEntry::new(":kinds", "List normalized structural kinds."),
    MetadataEntry::new(":roles", "List structural role fields."),
    MetadataEntry::new(":languages", "List language filter labels."),
    MetadataEntry::new(":json", "Print the current query as canonical JSON."),
    MetadataEntry::new(
        ":validate",
        "Validate the current query without running it.",
    ),
    MetadataEntry::new(":run", "Run the current query through query_code."),
    MetadataEntry::new(":clear", "Clear the current query."),
    MetadataEntry::new(":quit", "Exit the REPL."),
];

const EXAMPLES: &[Example] = &[
    Example::new(
        "calls",
        "Calls to a named callee with the first positional argument captured.",
        r#"(call :callee (name "eval") :args [(capture "arg")])"#,
    ),
    Example::new(
        "imports",
        "Imports of a specific module.",
        r#"(import :module (name "os"))"#,
    ),
    Example::new(
        "decorators",
        "Classes decorated with a specific annotation/decorator.",
        r#"(class :decorators [(name "Controller")])"#,
    ),
    Example::new(
        "scoped",
        "Calls scoped by path, language, and limit.",
        r#"(where "src/**/*.py" (language python (limit 25 (call :callee (name "eval")))))"#,
    ),
    Example::new(
        "inside",
        "Calls inside a named function.",
        r#"(inside (function :name "handler") (call :callee (name "eval")))"#,
    ),
];

const CTRL_C_QUIT_HINT: &str = "Press Ctrl+C again to quit...";

#[derive(Debug, Clone, Copy)]
struct MetadataEntry {
    name: &'static str,
    doc: &'static str,
}

impl MetadataEntry {
    const fn new(name: &'static str, doc: &'static str) -> Self {
        Self { name, doc }
    }
}

#[derive(Debug, Clone, Copy)]
struct Example {
    name: &'static str,
    doc: &'static str,
    query: &'static str,
}

impl Example {
    const fn new(name: &'static str, doc: &'static str, query: &'static str) -> Self {
        Self { name, doc, query }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReplFlow {
    Continue,
    Quit,
}

#[derive(Debug, Default)]
struct CtrlCQuitGuard {
    pending: bool,
}

impl CtrlCQuitGuard {
    fn reset(&mut self) {
        self.pending = false;
    }

    fn record_ctrl_c(&mut self) -> ReplFlow {
        if self.pending {
            ReplFlow::Quit
        } else {
            self.pending = true;
            ReplFlow::Continue
        }
    }
}

pub struct ReplSession {
    current_query: Option<Value>,
    use_color: bool,
}

impl ReplSession {
    pub fn new() -> Self {
        Self::with_color(false)
    }

    fn with_color(use_color: bool) -> Self {
        Self {
            current_query: None,
            use_color,
        }
    }

    pub fn process_line(
        &mut self,
        line: &str,
        service: Option<&SearchToolsService>,
    ) -> (ReplFlow, String) {
        let line = line.trim();
        if line.is_empty() {
            return (ReplFlow::Continue, String::new());
        }
        if line.starts_with(':') {
            return self.process_command(line, service);
        }
        match parse_query_input(line) {
            Ok(value) => {
                self.current_query = Some(value.clone());
                (ReplFlow::Continue, loaded_query_text(&value))
            }
            Err(error) => (
                ReplFlow::Continue,
                format!("error: {}", sanitize_terminal_text(&error)),
            ),
        }
    }

    fn process_command(
        &mut self,
        line: &str,
        service: Option<&SearchToolsService>,
    ) -> (ReplFlow, String) {
        let mut parts = line.split_whitespace();
        let command = parts.next().unwrap_or_default();
        let rest = parts.collect::<Vec<_>>().join(" ");
        match command {
            ":help" => (ReplFlow::Continue, help_text()),
            ":doc" => (ReplFlow::Continue, doc_text(rest.trim())),
            ":examples" => (ReplFlow::Continue, examples_text()),
            ":example" => match example_by_name(rest.trim()) {
                Some(example) => match parse_query_input(example.query) {
                    Ok(value) => {
                        self.current_query = Some(value);
                        (
                            ReplFlow::Continue,
                            format!(
                                "Loaded example `{}`: {}\n{}",
                                example.name, example.doc, example.query
                            ),
                        )
                    }
                    Err(error) => (ReplFlow::Continue, format!("error: {error}")),
                },
                None => (
                    ReplFlow::Continue,
                    format!(
                        "unknown example `{}`\n\n{}",
                        sanitize_terminal_text(rest.trim()),
                        examples_text()
                    ),
                ),
            },
            ":kinds" => (ReplFlow::Continue, kinds_text()),
            ":roles" => (ReplFlow::Continue, roles_text()),
            ":languages" => (ReplFlow::Continue, languages_text()),
            ":json" => match self.current_query.as_ref() {
                Some(value) => (ReplFlow::Continue, canonical_json_text(value)),
                None => (ReplFlow::Continue, "No current query.".to_string()),
            },
            ":validate" => match self.current_query.as_ref() {
                Some(value) => match CodeQuery::from_json(value) {
                    Ok(_) => (ReplFlow::Continue, "Query is valid.".to_string()),
                    Err(error) => (
                        ReplFlow::Continue,
                        format!("error: {}", sanitize_terminal_text(&error.to_string())),
                    ),
                },
                None => (ReplFlow::Continue, "No current query.".to_string()),
            },
            ":run" => match (self.current_query.as_ref(), service) {
                (Some(value), Some(service)) => (
                    ReplFlow::Continue,
                    run_query(service, value, self.use_color),
                ),
                (Some(_), None) => (
                    ReplFlow::Continue,
                    "No search service is attached to this REPL session.".to_string(),
                ),
                (None, _) => (ReplFlow::Continue, "No current query.".to_string()),
            },
            ":clear" => {
                self.current_query = None;
                (ReplFlow::Continue, "Query cleared.".to_string())
            }
            ":quit" | ":exit" => (ReplFlow::Quit, "bye".to_string()),
            other => (
                ReplFlow::Continue,
                format!(
                    "unknown command `{}`\n\n{}",
                    sanitize_terminal_text(other),
                    help_text()
                ),
            ),
        }
    }
}

impl Default for ReplSession {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_code_query_repl(root: PathBuf) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let mut service = LazySearchService::new(canonical_root);
    if io::stdin().is_terminal() {
        run_interactive(&mut service)
    } else {
        run_scripted(&mut service)
    }
}

struct LazySearchService {
    root: PathBuf,
    service: Option<SearchToolsService>,
}

impl LazySearchService {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            service: None,
        }
    }

    fn get_or_init(&mut self) -> Result<&SearchToolsService, String> {
        if self.service.is_none() {
            self.service = Some(SearchToolsService::new_without_semantic_index(
                self.root.clone(),
            )?);
        }
        Ok(self.service.as_ref().expect("service initialized"))
    }
}

fn run_interactive(service: &mut LazySearchService) -> Result<(), String> {
    let mut line_editor = configured_reedline();
    let prompt = DefaultPrompt::default();
    let mut session = ReplSession::with_color(should_colorize_repl());
    let mut ctrl_c_quit = CtrlCQuitGuard::default();
    println!("{}", welcome_text());
    loop {
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                ctrl_c_quit.reset();
                let (flow, output) = process_line_with_lazy_service(&mut session, &line, service)?;
                if !output.is_empty() {
                    println!("{output}");
                }
                if flow == ReplFlow::Quit {
                    return Ok(());
                }
            }
            Ok(Signal::CtrlD) => return Ok(()),
            Ok(Signal::CtrlC) => {
                if ctrl_c_quit.record_ctrl_c() == ReplFlow::Quit {
                    println!("bye");
                    return Ok(());
                }
                println!("{CTRL_C_QUIT_HINT}");
            }
            Ok(Signal::ExternalBreak(_)) => return Ok(()),
            Err(error) => return Err(format!("REPL input failed: {error}")),
            _ => {}
        }
    }
}

fn run_scripted(service: &mut LazySearchService) -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut session = ReplSession::new();
    let mut pending_query = String::new();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("Failed to read REPL input: {err}"))?;
        let Some(input) = accumulate_scripted_input(&mut pending_query, &line) else {
            continue;
        };
        let (flow, output) = process_line_with_lazy_service(&mut session, &input, service)?;
        if !output.is_empty() {
            writeln!(stdout, "{output}").map_err(|err| format!("Failed to write output: {err}"))?;
        }
        if flow == ReplFlow::Quit {
            break;
        }
    }
    if !pending_query.trim().is_empty() {
        let (flow, output) =
            process_line_with_lazy_service(&mut session, pending_query.trim(), service)?;
        if !output.is_empty() {
            writeln!(stdout, "{output}").map_err(|err| format!("Failed to write output: {err}"))?;
        }
        if flow == ReplFlow::Quit {
            return Ok(());
        }
    }
    Ok(())
}

fn process_line_with_lazy_service(
    session: &mut ReplSession,
    line: &str,
    service: &mut LazySearchService,
) -> Result<(ReplFlow, String), String> {
    if line.trim_start().starts_with(":run") {
        let service = service.get_or_init()?;
        Ok(session.process_line(line, Some(service)))
    } else {
        Ok(session.process_line(line, None))
    }
}

fn accumulate_scripted_input(pending_query: &mut String, line: &str) -> Option<String> {
    if pending_query.is_empty() && line.trim_start().starts_with(':') {
        return Some(line.to_string());
    }
    if !pending_query.is_empty() {
        pending_query.push('\n');
    }
    pending_query.push_str(line);
    if balanced_delimiters(pending_query) {
        Some(std::mem::take(pending_query))
    } else {
        None
    }
}

fn configured_reedline() -> Reedline {
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));
    let mut editor = Reedline::create()
        .with_completer(Box::new(ReplCompleter::new()))
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(Box::new(Emacs::new(keybindings)))
        .with_highlighter(Box::new(ReplHighlighter))
        .with_validator(Box::new(ReplValidator))
        .with_hinter(Box::new(DefaultHinter::default()));
    if let Some(path) = prepare_history_path()
        && let Ok(history) = FileBackedHistory::with_file(1000, path)
    {
        editor = editor.with_history(Box::new(history));
    }
    editor
}

fn history_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".bifrost_code_query_repl_history"))
}

fn prepare_history_path() -> Option<PathBuf> {
    let path = history_path()?;
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return None;
    }
    if ensure_private_history_file(&path).is_err() {
        return None;
    }
    Some(path)
}

#[cfg(unix)]
fn ensure_private_history_file(path: &PathBuf) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if !path.exists() {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn ensure_private_history_file(path: &PathBuf) -> io::Result<()> {
    if !path.exists() {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
    }
    Ok(())
}

fn parse_query_input(line: &str) -> Result<Value, String> {
    if line.trim_start().starts_with('{') {
        let value =
            serde_json::from_str(line).map_err(|error| format!("invalid JSON query: {error}"))?;
        CodeQuery::from_json(&value)
            .map(|query| query.to_canonical_json())
            .map_err(|error| error.to_string())
    } else {
        CodeQuery::from_sexp(line).map(|query| query.to_canonical_json())
    }
}

fn should_colorize_repl() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn loaded_query_text(value: &Value) -> String {
    match CodeQuery::from_json(value) {
        Ok(query) => format!(
            "Loaded {}.\nUse :run to execute it, or :json to inspect canonical JSON.",
            query_summary_text(&query)
        ),
        Err(error) => format!("error: {}", sanitize_terminal_text(&error.to_string())),
    }
}

fn canonical_json_text(value: &Value) -> String {
    match CodeQuery::from_json(value) {
        Ok(query) => serde_json::to_string_pretty(&query.to_canonical_json())
            .unwrap_or_else(|error| format!("error: failed to render canonical JSON: {error}")),
        Err(error) => format!("error: {}", sanitize_terminal_text(&error.to_string())),
    }
}

fn query_summary_text(query: &CodeQuery) -> String {
    let mut parts = vec![format!("{} query", pattern_summary(&query.root))];
    if !query.where_globs.is_empty() {
        let globs = query
            .where_globs
            .iter()
            .map(|glob| format!("\"{}\"", sanitize_terminal_text(glob.as_str())))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("where {globs}"));
    }
    if !query.languages.is_empty() {
        let languages = query
            .languages
            .iter()
            .map(|language| language.config_label())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("language {languages}"));
    }
    if let Some(pattern) = &query.inside {
        parts.push(format!("inside {}", pattern_summary(pattern)));
    }
    if let Some(pattern) = &query.not_inside {
        parts.push(format!("not inside {}", pattern_summary(pattern)));
    }
    parts.push(format!("limit {}", query.limit));
    parts.push(format!("detail {}", query.result_detail.label()));
    parts.join("; ")
}

fn pattern_summary(pattern: &Pattern) -> String {
    let mut parts = Vec::new();
    if pattern.kinds.is_empty() {
        parts.push("structural".to_string());
    } else {
        parts.push(
            pattern
                .kinds
                .iter()
                .map(|kind| kind.label())
                .collect::<Vec<_>>()
                .join("|"),
        );
    }
    if let Some(predicate) = &pattern.name {
        parts.push(predicate_summary("name", predicate));
    }
    if let Some(predicate) = &pattern.text {
        parts.push(predicate_summary("text", predicate));
    }
    if let Some(capture) = &pattern.capture {
        parts.push(format!("capture \"{}\"", sanitize_terminal_text(capture)));
    }
    if !pattern.not_kinds.is_empty() {
        parts.push(format!(
            "not {}",
            pattern
                .not_kinds
                .iter()
                .map(|kind| kind.label())
                .collect::<Vec<_>>()
                .join("|")
        ));
    }
    parts.join(" ")
}

fn predicate_summary(field: &str, predicate: &StringPredicate) -> String {
    match predicate {
        StringPredicate::Exact(value) => {
            format!("{field} \"{}\"", sanitize_terminal_text(value))
        }
        StringPredicate::Regex(regex) => {
            format!("{field} /{}/", sanitize_terminal_text(regex.as_str()))
        }
    }
}

fn run_query(service: &SearchToolsService, value: &Value, use_color: bool) -> String {
    match service.query_code_result(value.clone()) {
        Ok(output) => render_code_query_repl_output(&output, use_color),
        Err(error) => format!("error: {}", sanitize_terminal_text(&error.to_string())),
    }
}

fn render_code_query_repl_output(output: &CodeQueryResult, use_color: bool) -> String {
    let mut out = String::new();
    if output.matches.is_empty() {
        out.push_str("No structural matches.\n");
    } else {
        out.push_str(&format!("{}\n", output.match_count_line()));
        for matched in &output.matches {
            out.push('\n');
            render_code_query_match(&mut out, matched, use_color);
        }
    }

    for diagnostic in &output.diagnostics {
        out.push_str(&format!(
            "{} {}\n",
            paint(Style::new().fg(Color::Yellow), "note:", use_color),
            sanitize_terminal_text(&diagnostic.message)
        ));
    }
    out
}

fn render_code_query_match(out: &mut String, matched: &CodeQueryMatch, use_color: bool) {
    let path = sanitize_terminal_text(&matched.path);
    let kind = sanitize_terminal_text(matched.kind);
    let text = sanitize_terminal_text(&matched.text);
    let lines = matched.line_span_label();

    out.push_str(&format!(
        "{}:{}\n",
        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
        paint(Style::new().fg(Color::Purple), &lines, use_color)
    ));
    out.push_str(&format!(
        "  {} {}\n",
        paint(Style::new().fg(Color::Blue), "kind:", use_color),
        paint(Style::new().fg(Color::Yellow), &kind, use_color)
    ));
    if let Some(enclosing) = &matched.enclosing_symbol {
        let enclosing = sanitize_terminal_text(enclosing);
        out.push_str(&format!(
            "  {} {}\n",
            paint(Style::new().fg(Color::Blue), "symbol:", use_color),
            paint(Style::new().bold(), &enclosing, use_color)
        ));
    }
    out.push_str(&format!(
        "  {} {}\n",
        paint(Style::new().fg(Color::Blue), "code:", use_color),
        paint(
            Style::new().fg(Color::Green),
            &format!("`{text}`"),
            use_color
        )
    ));

    for capture in &matched.captures {
        let name = sanitize_terminal_text(&capture.name);
        let capture_text = sanitize_terminal_text(&capture.text);
        out.push_str(&format!(
            "  {} {} = {} {}\n",
            paint(Style::new().fg(Color::Blue), "capture:", use_color),
            paint(
                Style::new().fg(Color::Purple),
                &format!("${name}"),
                use_color
            ),
            paint(
                Style::new().fg(Color::Green),
                &format!("`{capture_text}`"),
                use_color
            ),
            paint(
                Style::new().dimmed(),
                &format!("line {}", capture.start_line),
                use_color
            )
        ));
    }
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            '\t' => sanitized.push_str("\\t"),
            '\u{1b}' => sanitized.push_str("\\x1b"),
            '\u{07}' => sanitized.push_str("\\x07"),
            ch if ch.is_control() => {
                sanitized.push_str(&format!("\\u{{{:x}}}", ch as u32));
            }
            ch => sanitized.push(ch),
        }
    }
    sanitized
}

fn paint(style: Style, text: &str, use_color: bool) -> String {
    if use_color {
        style.paint(text).to_string()
    } else {
        text.to_string()
    }
}

fn welcome_text() -> String {
    "Bifrost code-query REPL. Type :help for commands. S-expressions are the human query syntax."
        .to_string()
}

fn help_text() -> String {
    let mut lines = vec![
        "Commands:".to_string(),
        "  :help                  Show this help.".to_string(),
        "  :doc <name>            Show docs for commands, kinds, roles, wrappers, or examples."
            .to_string(),
        "  :examples              List named examples.".to_string(),
        "  :example <name>        Load a named example.".to_string(),
        "  :kinds | :roles        List query vocabulary.".to_string(),
        "  :languages             List language labels.".to_string(),
        "  :json                  Print canonical JSON for the current query.".to_string(),
        "  :validate              Validate the current query.".to_string(),
        "  :run                   Execute the current query.".to_string(),
        "  :clear | :quit         Clear query or exit.".to_string(),
        String::new(),
        "S-expression examples:".to_string(),
    ];
    lines.extend(
        EXAMPLES
            .iter()
            .map(|example| format!("  {:<10} {}  {}", example.name, example.query, example.doc)),
    );
    lines.push(String::new());
    lines.push("JSON objects are accepted too; use :json to print canonical JSON.".to_string());
    lines.join("\n")
}

fn examples_text() -> String {
    EXAMPLES
        .iter()
        .map(|example| format!("{:<10} {} — {}", example.name, example.query, example.doc))
        .collect::<Vec<_>>()
        .join("\n")
}

fn kinds_text() -> String {
    ALL_KINDS
        .iter()
        .map(|kind| kind.label())
        .collect::<Vec<_>>()
        .join("\n")
}

fn roles_text() -> String {
    ALL_ROLES
        .iter()
        .map(|role| format!(":{:<12} {}", role.label(), role.description()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn languages_text() -> String {
    Language::ANALYZABLE
        .iter()
        .map(|language| language.config_label())
        .collect::<Vec<_>>()
        .join("\n")
}

fn doc_text(name: &str) -> String {
    if name.is_empty() {
        return "usage: :doc <name>".to_string();
    }
    let normalized = name.trim_start_matches(':');
    if let Some(command) = COMMANDS.iter().find(|entry| entry.name == name) {
        return format!("{} — {}", command.name, command.doc);
    }
    if let Some(form) = ALL_RQL_FORMS
        .iter()
        .find(|form| form.labels().contains(&normalized))
    {
        return format!(
            "{} — {}\n{}",
            form.label(),
            form.description(),
            form.signature()
        );
    }
    if let Some(example) = example_by_name(normalized) {
        return format!("{} — {}\n{}", example.name, example.doc, example.query);
    }
    if let Some(kind) = ALL_KINDS.iter().find(|kind| kind.label() == normalized) {
        return format!(
            "{} — {} Subtype parent: {}",
            kind.label(),
            kind.description(),
            kind.parent().map_or("none", |parent| parent.label())
        );
    }
    if let Some(role) = Role::from_label(normalized) {
        return format!(
            ":{} — {}\n:{} {}",
            role.label(),
            role.description(),
            role.label(),
            role.signature()
        );
    }
    if Language::ANALYZABLE
        .iter()
        .any(|language| language.config_label() == normalized)
    {
        return format!("{normalized} — language filter label for query_code.");
    }
    format!("No docs for `{name}`.")
}

fn example_by_name(name: &str) -> Option<&'static Example> {
    EXAMPLES.iter().find(|example| example.name == name)
}

#[derive(Clone)]
struct ReplCompleter {
    entries: Vec<CompletionEntry>,
}

#[derive(Clone)]
struct CompletionEntry {
    value: String,
    description: String,
}

impl ReplCompleter {
    fn new() -> Self {
        let mut entries = Vec::new();
        entries.extend(COMMANDS.iter().map(|entry| CompletionEntry {
            value: entry.name.to_string(),
            description: entry.doc.to_string(),
        }));
        entries.extend(ALL_RQL_FORMS.iter().flat_map(|form| {
            form.labels().iter().map(|label| CompletionEntry {
                value: (*label).to_string(),
                description: form.description().to_string(),
            })
        }));
        entries.extend(ALL_KINDS.iter().map(|kind| CompletionEntry {
            value: kind.label().to_string(),
            description: kind.description().to_string(),
        }));
        entries.extend(ALL_ROLES.iter().map(|role| CompletionEntry {
            value: format!(":{}", role.label()),
            description: role.description().to_string(),
        }));
        entries.extend(Language::ANALYZABLE.iter().map(|language| CompletionEntry {
            value: language.config_label().to_string(),
            description: "language filter label".to_string(),
        }));
        entries.extend(EXAMPLES.iter().map(|example| CompletionEntry {
            value: example.name.to_string(),
            description: example.doc.to_string(),
        }));
        Self { entries }
    }
}

impl Completer for ReplCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let (start, prefix) = completion_prefix(line, pos);
        self.entries
            .iter()
            .filter(|entry| entry.value.starts_with(prefix))
            .map(|entry| Suggestion {
                value: entry.value.clone(),
                description: Some(entry.description.clone()),
                span: ReedlineSpan::new(start, pos),
                append_whitespace: !entry.value.starts_with(':'),
                ..Suggestion::default()
            })
            .collect()
    }
}

fn completion_prefix(line: &str, pos: usize) -> (usize, &str) {
    let pos = pos.min(line.len());
    let mut start = pos;
    for (index, ch) in line[..pos].char_indices().rev() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | ':') {
            start = index;
        } else {
            break;
        }
    }
    (start, &line[start..pos])
}

struct ReplValidator;

impl Validator for ReplValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        if balanced_delimiters(line) {
            ValidationResult::Complete
        } else {
            ValidationResult::Incomplete
        }
    }
}

struct ReplHighlighter;

impl Highlighter for ReplHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        let mut styled = StyledText::new();
        if line.starts_with(':') {
            styled.push((Style::new().fg(Color::Cyan), line.to_string()));
        } else {
            styled.push((Style::new().fg(Color::Green), line.to_string()));
        }
        styled
    }
}

fn balanced_delimiters(line: &str) -> bool {
    let mut parens = 0isize;
    let mut brackets = 0isize;
    let mut in_string = false;
    let mut escaped = false;
    for ch in line.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => parens += 1,
            ')' => parens -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            _ => {}
        }
        if parens < 0 || brackets < 0 {
            return true;
        }
    }
    !in_string && parens == 0 && brackets == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost::analyzer::structural::CodeQueryCapture;

    #[test]
    fn code_query_repl_loads_sexp_with_human_summary() {
        let mut session = ReplSession::new();
        let (_flow, output) = session.process_line(r#"(call :callee (name "eval"))"#, None);
        assert!(output.contains("Loaded call query"), "{output}");
        assert!(
            output.contains("Use :run to execute it, or :json to inspect canonical JSON."),
            "{output}"
        );
        assert!(!output.contains("\"kind\": \"call\""), "{output}");

        let (_flow, output) = session.process_line(":json", None);
        assert!(output.contains("\"kind\": \"call\""), "{output}");
        assert!(output.contains("\"name\": \"eval\""), "{output}");
    }

    #[test]
    fn code_query_repl_sanitizes_loaded_query_summary() {
        let mut session = ReplSession::new();
        let (_flow, output) =
            session.process_line(r#"(function :name "\u001b]52;c;secret\u0007")"#, None);
        assert!(!output.contains('\u{1b}'), "{output:?}");
        assert!(!output.contains('\u{07}'), "{output:?}");
        assert!(output.contains("\\x1b"), "{output}");
        assert!(output.contains("\\x07"), "{output}");
    }

    #[test]
    fn code_query_repl_validates_current_query() {
        let mut session = ReplSession::new();
        session.process_line(r#"(call :callee (name "eval"))"#, None);
        let (_flow, output) = session.process_line(":validate", None);
        assert_eq!(output, "Query is valid.");
    }

    #[test]
    fn code_query_repl_exposes_doc_metadata() {
        assert!(doc_text(":run").contains("Run"));
        assert!(doc_text("call").contains("Match call"));
        assert!(doc_text("comments").contains("comment"));
        assert!(doc_text("callee").contains("call target"));
        assert!(doc_text("calls").contains("eval"));
    }

    #[test]
    fn code_query_repl_examples_all_parse() {
        for example in EXAMPLES {
            parse_query_input(example.query)
                .unwrap_or_else(|error| panic!("example `{}` should parse: {error}", example.name));
        }
    }

    #[test]
    fn code_query_repl_completes_commands_and_roles_with_descriptions() {
        let mut completer = ReplCompleter::new();
        let suggestions = completer.complete(":r", 2);
        assert!(
            suggestions
                .iter()
                .any(|suggestion| suggestion.value == ":run")
        );
        assert!(
            suggestions
                .iter()
                .any(|suggestion| suggestion.description.is_some())
        );

        let suggestions = completer.complete("(call :cal", 10);
        assert!(
            suggestions
                .iter()
                .any(|suggestion| suggestion.value == ":callee")
        );
    }

    #[test]
    fn code_query_repl_validator_accepts_multiline_until_balanced() {
        let validator = ReplValidator;
        assert!(matches!(
            validator.validate(r#"(call :callee (name "eval")"#),
            ValidationResult::Incomplete
        ));
        assert!(matches!(
            validator.validate(r#"(call :callee (name "eval"))"#),
            ValidationResult::Complete
        ));
    }

    #[test]
    fn code_query_repl_accumulates_scripted_multiline_queries() {
        let mut pending = String::new();
        assert_eq!(accumulate_scripted_input(&mut pending, "(class"), None);
        assert_eq!(
            accumulate_scripted_input(&mut pending, r#"  :name "A")"#),
            Some("(class\n  :name \"A\")".to_string())
        );
        assert_eq!(
            accumulate_scripted_input(&mut pending, ":validate"),
            Some(":validate".to_string())
        );
    }

    #[test]
    fn code_query_repl_ctrl_c_quits_only_after_second_consecutive_signal() {
        let mut guard = CtrlCQuitGuard::default();
        assert_eq!(guard.record_ctrl_c(), ReplFlow::Continue);
        guard.reset();
        assert_eq!(guard.record_ctrl_c(), ReplFlow::Continue);
        assert_eq!(guard.record_ctrl_c(), ReplFlow::Quit);
    }

    #[test]
    fn code_query_repl_renders_query_code_matches_as_multiline_entries() {
        let output = render_code_query_repl_output(
            &CodeQueryResult {
                matches: vec![CodeQueryMatch {
                    path: "editors/vscode/src/provisioning.ts".to_string(),
                    language: "typescript",
                    kind: "function",
                    start_line: 259,
                    end_line: 269,
                    text: "async function probeBifrostVersion(binaryPath: string): Promise<VersionProbe> {…".to_string(),
                    id: None,
                    node_range: None,
                    decorated_range: None,
                    decorator_ranges: Vec::new(),
                    captures: vec![CodeQueryCapture {
                        name: "callee".to_string(),
                        text: "probe".to_string(),
                        start_line: 260,
                        range: None,
                        kind: None,
                    }],
                    enclosing_symbol: Some("probeBifrostVersion".to_string()),
                }],
                truncated: false,
                diagnostics: Vec::new(),
            },
            false,
        );

        assert!(output.contains("1 match"), "{output}");
        assert!(
            output.contains("editors/vscode/src/provisioning.ts:259-269"),
            "{output}"
        );
        assert!(output.contains("  kind: function"), "{output}");
        assert!(output.contains("  symbol: probeBifrostVersion"), "{output}");
        assert!(
            output.contains("  code: `async function probeBifrostVersion"),
            "{output}"
        );
        assert!(
            output.contains("  capture: $callee = `probe` line 260"),
            "{output}"
        );
    }

    #[test]
    fn code_query_repl_sanitizes_terminal_control_sequences() {
        let output = render_code_query_repl_output(
            &CodeQueryResult {
                matches: vec![CodeQueryMatch {
                    path: "src/\u{1b}]52;c;secret\u{07}.rs".to_string(),
                    language: "rust",
                    kind: "function",
                    start_line: 1,
                    end_line: 1,
                    text: "fn demo() {}\u{1b}[2J".to_string(),
                    id: None,
                    node_range: None,
                    decorated_range: None,
                    decorator_ranges: Vec::new(),
                    captures: Vec::new(),
                    enclosing_symbol: None,
                }],
                truncated: false,
                diagnostics: Vec::new(),
            },
            false,
        );

        assert!(!output.contains('\u{1b}'), "{output:?}");
        assert!(!output.contains('\u{07}'), "{output:?}");
        assert!(output.contains("\\x1b"), "{output}");
        assert!(output.contains("\\x07"), "{output}");
    }
}
