use brokk_bifrost::analyzer::structural::kinds::{ALL_KINDS, ALL_ROLES, Role};
use brokk_bifrost::analyzer::structural::query::schema::ALL_RQL_FORMS;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryMatch, CodeQueryPlan, CodeQueryPlanSource, CodeQueryResponse,
    CodeQueryResult, CodeQueryResultValue, Pattern, RuneIrLanguage, RuneIrLimits, RuneIrSelection,
    StringPredicate, render_source_rune_ir,
};
use brokk_bifrost::{Language, SearchToolsService};
use nu_ansi_term::{Color, Style};
use reedline::{
    ColumnarMenu, Completer, DefaultHinter, DefaultPrompt, Emacs, FileBackedHistory, Highlighter,
    History, HistoryItem, HistoryItemId, HistorySessionId, KeyCode, KeyModifiers, MenuBuilder,
    Reedline, ReedlineEvent, ReedlineMenu, SearchQuery, Signal, Span as ReedlineSpan, StyledText,
    Suggestion, ValidationResult, Validator, default_emacs_keybindings,
};
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    MetadataEntry::new(
        ":ir",
        "Capture source through :end and print its Rune IR plus starter RQL.",
    ),
    MetadataEntry::new(":json", "Print the current query as canonical JSON."),
    MetadataEntry::new(
        ":validate",
        "Validate the current query without running it.",
    ),
    MetadataEntry::new(":run", "Run the current query through query_code."),
    MetadataEntry::new(":clear", "Clear the current query."),
    MetadataEntry::new(":quit", "Exit the REPL."),
];

const LANGUAGE_TOPICS: &[MetadataEntry] = &[MetadataEntry::new(
    "comments",
    "Use ; at a token boundary for a comment through the next newline; RQL has no block comments.",
)];

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
    Example::new(
        "hierarchy-members",
        "Members declared by every indexed transitive subtype of a named type.",
        r#"(members (subtypes :transitive true (enclosing-decl (class :name "Service"))))"#,
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
    rune_ir_capture: Option<RuneIrCapture>,
    rune_ir_capture_mode: Arc<AtomicBool>,
    use_color: bool,
}

struct RuneIrCapture {
    language: RuneIrLanguage,
    source: String,
    has_lines: bool,
}

impl ReplSession {
    pub fn new() -> Self {
        Self::with_color(false)
    }

    fn with_color(use_color: bool) -> Self {
        Self::with_capture_mode(use_color, Arc::new(AtomicBool::new(false)))
    }

    fn with_capture_mode(use_color: bool, rune_ir_capture_mode: Arc<AtomicBool>) -> Self {
        Self {
            current_query: None,
            rune_ir_capture: None,
            rune_ir_capture_mode,
            use_color,
        }
    }

    pub fn process_line(
        &mut self,
        line: &str,
        service: Option<&SearchToolsService>,
    ) -> (ReplFlow, String) {
        if self.rune_ir_capture.is_some() {
            return self.process_rune_ir_line(line);
        }
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
            ":ir" => self.start_rune_ir_capture(rest.trim()),
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

    fn start_rune_ir_capture(&mut self, label: &str) -> (ReplFlow, String) {
        if label.is_empty() {
            return (
                ReplFlow::Continue,
                "usage: :ir <language>; finish source input with :end".to_string(),
            );
        }
        let Some(language) = RuneIrLanguage::from_config_label(label) else {
            return (
                ReplFlow::Continue,
                format!(
                    "unsupported Rune IR language `{}`; use :languages to list supported labels",
                    sanitize_terminal_text(label)
                ),
            );
        };
        self.rune_ir_capture = Some(RuneIrCapture {
            language,
            source: String::new(),
            has_lines: false,
        });
        self.rune_ir_capture_mode.store(true, Ordering::Relaxed);
        (
            ReplFlow::Continue,
            format!(
                "Capturing {} source for Rune IR. Enter :end on its own line to render.",
                language.config_label()
            ),
        )
    }

    fn process_rune_ir_line(&mut self, line: &str) -> (ReplFlow, String) {
        if line.trim() != ":end" {
            let input_limit = RuneIrLimits::default().max_input_bytes;
            let capture = self
                .rune_ir_capture
                .as_mut()
                .expect("capture checked above");
            let separator_bytes = usize::from(capture.has_lines);
            if capture
                .source
                .len()
                .saturating_add(separator_bytes)
                .saturating_add(line.len())
                > input_limit
            {
                self.rune_ir_capture = None;
                self.rune_ir_capture_mode.store(false, Ordering::Relaxed);
                return (
                    ReplFlow::Continue,
                    format!(
                        "error: Rune IR source exceeds the {input_limit}-byte input limit; capture cancelled"
                    ),
                );
            }
            if capture.has_lines {
                capture.source.push('\n');
            }
            capture.source.push_str(line);
            capture.has_lines = true;
            return (ReplFlow::Continue, String::new());
        }

        let capture = self.rune_ir_capture.take().expect("capture checked above");
        self.rune_ir_capture_mode.store(false, Ordering::Relaxed);
        let result = render_source_rune_ir(
            capture.language,
            &capture.source,
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        );
        let output = match result {
            Ok(rendered) => {
                let rune_ir = sanitize_terminal_document(rendered.rune_ir.trim_end());
                let starter_rql = sanitize_terminal_text(&rendered.starter_rql);
                format!(
                    "Rune IR ({}):\n{rune_ir}\nStarter RQL:\n{starter_rql}",
                    capture.language.config_label()
                )
            }
            Err(error) => format!("error: {}", sanitize_terminal_text(&error.to_string())),
        };
        (ReplFlow::Continue, output)
    }

    fn is_capturing_rune_ir(&self) -> bool {
        self.rune_ir_capture.is_some()
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
    let rune_ir_capture_mode = Arc::new(AtomicBool::new(false));
    let mut line_editor = configured_reedline(Arc::clone(&rune_ir_capture_mode));
    let prompt = DefaultPrompt::default();
    let mut session = ReplSession::with_capture_mode(should_colorize_repl(), rune_ir_capture_mode);
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
        if session.is_capturing_rune_ir() {
            let (flow, output) = process_line_with_lazy_service(&mut session, &line, service)?;
            if !output.is_empty() {
                writeln!(stdout, "{output}")
                    .map_err(|err| format!("Failed to write output: {err}"))?;
            }
            if flow == ReplFlow::Quit {
                break;
            }
            continue;
        }
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
    if !session.is_capturing_rune_ir() && line.trim_start().starts_with(":run") {
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

fn configured_reedline(rune_ir_capture_mode: Arc<AtomicBool>) -> Reedline {
    let history_capture_mode = Arc::clone(&rune_ir_capture_mode);
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
        .with_validator(Box::new(ReplValidator {
            rune_ir_capture_mode,
        }))
        .with_hinter(Box::new(DefaultHinter::default()));
    if let Some(path) = prepare_history_path()
        && let Ok(history) = FileBackedHistory::with_file(1000, path)
    {
        editor = editor.with_history(Box::new(CaptureFilteringHistory::new(
            history,
            history_capture_mode,
        )));
    }
    editor
}

struct CaptureFilteringHistory {
    inner: FileBackedHistory,
    rune_ir_capture_mode: Arc<AtomicBool>,
}

impl CaptureFilteringHistory {
    fn new(inner: FileBackedHistory, rune_ir_capture_mode: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            rune_ir_capture_mode,
        }
    }
}

impl History for CaptureFilteringHistory {
    fn save(&mut self, mut item: HistoryItem) -> reedline::Result<HistoryItem> {
        if self.rune_ir_capture_mode.load(Ordering::Relaxed) {
            item.id = None;
            return Ok(item);
        }
        self.inner.save(item)
    }

    fn load(&self, id: HistoryItemId) -> reedline::Result<HistoryItem> {
        self.inner.load(id)
    }

    fn count(&self, query: SearchQuery) -> reedline::Result<i64> {
        self.inner.count(query)
    }

    fn search(&self, query: SearchQuery) -> reedline::Result<Vec<HistoryItem>> {
        self.inner.search(query)
    }

    fn update(
        &mut self,
        id: HistoryItemId,
        updater: &dyn Fn(HistoryItem) -> HistoryItem,
    ) -> reedline::Result<()> {
        self.inner.update(id, updater)
    }

    fn clear(&mut self) -> reedline::Result<()> {
        self.inner.clear()
    }

    fn delete(&mut self, id: HistoryItemId) -> reedline::Result<()> {
        self.inner.delete(id)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.inner.sync()
    }

    fn session(&self) -> Option<HistorySessionId> {
        self.inner.session()
    }
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
    let mut parts = vec![plan_summary_text(&query.plan)];
    parts.push(format!("limit {}", query.limit));
    parts.push(format!("detail {}", query.result_detail.label()));
    parts.push(format!("mode {}", query.execution_mode.label()));
    parts.join("; ")
}

fn plan_summary_text(plan: &CodeQueryPlan) -> String {
    let mut parts = match &plan.source {
        CodeQueryPlanSource::Seed(seed) => {
            let mut parts = vec![format!("{} query", pattern_summary(&seed.root))];
            if !seed.where_globs.is_empty() {
                let globs = seed
                    .where_globs
                    .iter()
                    .map(|glob| format!("\"{}\"", sanitize_terminal_text(glob.as_str())))
                    .collect::<Vec<_>>()
                    .join(", ");
                parts.push(format!("where {globs}"));
            }
            if !seed.languages.is_empty() {
                let languages = seed
                    .languages
                    .iter()
                    .map(|language| language.config_label())
                    .collect::<Vec<_>>()
                    .join(", ");
                parts.push(format!("language {languages}"));
            }
            if let Some(pattern) = &seed.inside {
                parts.push(format!("inside {}", pattern_summary(pattern)));
            }
            if let Some(pattern) = &seed.not_inside {
                parts.push(format!("not inside {}", pattern_summary(pattern)));
            }
            parts
        }
        CodeQueryPlanSource::Set { op, branches } => {
            vec![format!("{} of {} queries", op.label(), branches.len())]
        }
    };
    if !plan.steps.is_empty() {
        parts.push(format!(
            "steps {}",
            plan.steps
                .iter()
                .map(|step| step.label())
                .collect::<Vec<_>>()
                .join(" -> ")
        ));
    }
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
        Ok(CodeQueryResponse::Results(output)) => render_code_query_repl_output(&output, use_color),
        Ok(CodeQueryResponse::Explain(explain)) => format!(
            "CodeQuery explain (planning only):\n{}",
            serde_json::to_string_pretty(&explain)
                .expect("the public CodeQuery explain model is serializable")
        ),
        Ok(CodeQueryResponse::Profile(profile)) => {
            let mut rendered = render_code_query_repl_output(&profile.result, use_color);
            rendered.push_str("\nCodeQuery profile report:\n");
            rendered.push_str(
                &serde_json::to_string_pretty(&profile)
                    .expect("the public CodeQuery profile report is serializable"),
            );
            rendered.push('\n');
            rendered
        }
        Err(error) => format!("error: {}", sanitize_terminal_text(&error.to_string())),
    }
}

fn render_code_query_repl_output(output: &CodeQueryResult, use_color: bool) -> String {
    let mut out = String::new();
    if output.results.is_empty() {
        out.push_str("No query results.\n");
    } else {
        out.push_str(&format!("{}\n", output.result_count_line()));
        for result in &output.results {
            out.push('\n');
            match &result.value {
                CodeQueryResultValue::StructuralMatch { value } => {
                    render_code_query_match(&mut out, value, use_color);
                }
                CodeQueryResultValue::Declaration { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    let name = sanitize_terminal_text(&value.fq_name);
                    out.push_str(&format!(
                        "{}:{}-{}\n  {} {}\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        value.start_line,
                        value.end_line,
                        paint(Style::new().fg(Color::Blue), "declaration:", use_color),
                        paint(Style::new().bold(), &name, use_color)
                    ));
                }
                CodeQueryResultValue::File { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    out.push_str(&format!(
                        "{}\n  {} {}\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        paint(Style::new().fg(Color::Blue), "language:", use_color),
                        value.language
                    ));
                }
                CodeQueryResultValue::ReferenceSite { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    let target = sanitize_terminal_text(&value.target.fq_name);
                    out.push_str(&format!(
                        "{}:{}:{}\n  {} {} ({})\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        value.range.start_line,
                        value.range.start_column,
                        paint(Style::new().fg(Color::Blue), "reference:", use_color),
                        paint(Style::new().bold(), &target, use_color),
                        value.proof
                    ));
                }
                CodeQueryResultValue::CallSite { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    let caller = sanitize_terminal_text(&value.caller.fq_name);
                    let callee = sanitize_terminal_text(&value.callee.fq_name);
                    out.push_str(&format!(
                        "{}:{}:{}\n  {} {} -> {} ({})\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        value.range.start_line,
                        value.range.start_column,
                        paint(Style::new().fg(Color::Blue), "call:", use_color),
                        paint(Style::new().bold(), &caller, use_color),
                        paint(Style::new().bold(), &callee, use_color),
                        value.proof
                    ));
                }
                CodeQueryResultValue::ExpressionSite { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    let text = sanitize_terminal_text(&value.text);
                    out.push_str(&format!(
                        "{}:{}:{}\n  {} `{}` ({})\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        value.range.start_line,
                        value.range.start_column,
                        paint(Style::new().fg(Color::Blue), "call input:", use_color),
                        text,
                        value.input_kind
                    ));
                }
                CodeQueryResultValue::ReceiverAnalysis { value } => {
                    let path = sanitize_terminal_text(&value.path);
                    let text = sanitize_terminal_text(&value.text);
                    out.push_str(&format!(
                        "{}:{}:{}\n  {} `{}` ({})\n",
                        paint(Style::new().fg(Color::Cyan).bold(), &path, use_color),
                        value.range.start_line,
                        value.range.start_column,
                        paint(
                            Style::new().fg(Color::Blue),
                            "receiver analysis:",
                            use_color
                        ),
                        text,
                        value.outcome
                    ));
                    for detail in value.render_detail_lines() {
                        out.push_str(&format!("  {}\n", sanitize_terminal_text(&detail)));
                    }
                }
            }
            if !result.provenance.is_empty() {
                let mut branch_labels = Vec::new();
                for trace in &result.provenance {
                    let label = format_branch_path(&trace.branch);
                    if !label.is_empty() && !branch_labels.contains(&label) {
                        branch_labels.push(label);
                    }
                }
                out.push_str(&format!(
                    "  provenance: {} path{}{}{}\n",
                    result.provenance.len(),
                    if result.provenance.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    if result.provenance_truncated {
                        " (truncated)"
                    } else {
                        ""
                    },
                    if branch_labels.is_empty() {
                        String::new()
                    } else {
                        format!("; branches {}", branch_labels.join(", "))
                    },
                ));
            }
        }
    }

    for diagnostic in &output.diagnostics {
        let kind = format!(
            "{} [{}]",
            diagnostic.impact.as_str(),
            diagnostic.code.as_str()
        );
        let label = if diagnostic.branch.is_empty() {
            format!("{kind}:")
        } else {
            format!(
                "{kind} [branch {}]:",
                format_branch_path(&diagnostic.branch)
            )
        };
        out.push_str(&format!(
            "{} {}\n",
            paint(Style::new().fg(Color::Yellow), &label, use_color),
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

fn format_branch_path(branch: &[usize]) -> String {
    branch
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for ch in text.chars() {
        push_terminal_safe_char(&mut sanitized, ch, false);
    }
    sanitized
}

fn sanitize_terminal_document(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for ch in text.chars() {
        push_terminal_safe_char(&mut sanitized, ch, true);
    }
    sanitized
}

fn push_terminal_safe_char(sanitized: &mut String, ch: char, preserve_newlines: bool) {
    match ch {
        '\n' if preserve_newlines => sanitized.push('\n'),
        '\n' => sanitized.push_str("\\n"),
        '\r' => sanitized.push_str("\\r"),
        '\t' => sanitized.push_str("\\t"),
        '\u{1b}' => sanitized.push_str("\\x1b"),
        '\u{07}' => sanitized.push_str("\\x07"),
        ch if ch.is_control() || is_unicode_directional_control(ch) => {
            sanitized.push_str(&format!("\\u{{{:x}}}", ch as u32));
        }
        ch => sanitized.push(ch),
    }
}

fn is_unicode_directional_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
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
        "  :ir <language>         Capture source through :end and print Rune IR plus starter RQL."
            .to_string(),
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
    RuneIrLanguage::config_labels()
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
    if let Some(topic) = LANGUAGE_TOPICS
        .iter()
        .find(|entry| entry.name == normalized)
    {
        return format!("{} — {}", topic.name, topic.doc);
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
    if normalized == "tsx" {
        return "tsx — Rune IR parser label for TypeScript source containing JSX.".to_string();
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
        entries.extend(LANGUAGE_TOPICS.iter().map(|entry| CompletionEntry {
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
        entries.extend(
            RuneIrLanguage::config_labels().map(|label| CompletionEntry {
                value: label.to_string(),
                description: if label == "tsx" {
                    "Rune IR parser label for TypeScript source containing JSX".to_string()
                } else {
                    "language filter and Rune IR parser label".to_string()
                },
            }),
        );
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

struct ReplValidator {
    rune_ir_capture_mode: Arc<AtomicBool>,
}

impl Validator for ReplValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        if self.rune_ir_capture_mode.load(Ordering::Relaxed) || balanced_delimiters(line) {
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
    use brokk_bifrost::analyzer::structural::{CodeQueryCapture, CodeQueryResultItem};

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
    fn code_query_repl_runs_explain_and_profile_modes() {
        let temp = tempfile::tempdir().expect("temp dir");
        fs::write(temp.path().join("app.py"), "class App:\n    pass\n").expect("write source");
        let service = SearchToolsService::new_without_semantic_index(temp.path().to_path_buf())
            .expect("search service");
        let mut session = ReplSession::new();

        let (_, loaded) = session.process_line("(explain (class :name \"App\"))", None);
        assert!(loaded.contains("mode explain"), "{loaded}");
        let (_, canonical) = session.process_line(":json", None);
        assert!(
            canonical.contains("\"execution_mode\": \"explain\""),
            "{canonical}"
        );
        let (_, explain) = session.process_line(":run", Some(&service));
        assert!(explain.contains("planning only"), "{explain}");
        assert!(
            explain.contains("bifrost_code_query_explain/v1"),
            "{explain}"
        );

        session.process_line("(profile (class :name \"App\"))", None);
        let (_, profile) = session.process_line(":run", Some(&service));
        assert!(profile.contains("class App"), "{profile}");
        assert!(profile.contains("CodeQuery profile report:"), "{profile}");
        assert!(profile.contains("\"result\""), "{profile}");
        assert!(profile.contains("\"cache_layers\""), "{profile}");
        assert!(profile.contains("\"operators\""), "{profile}");
        assert!(profile.contains("\"peak_concurrency\": 1"), "{profile}");
    }

    #[test]
    fn code_query_repl_exposes_doc_metadata() {
        assert!(doc_text(":run").contains("Run"));
        assert!(doc_text(":ir").contains("Rune IR"));
        assert!(doc_text("call").contains("Match call"));
        assert!(doc_text("comments").contains("no block comments"));
        assert!(doc_text("callee").contains("call target"));
        assert!(doc_text("calls").contains("eval"));
    }

    #[test]
    fn code_query_repl_renders_multiline_rune_ir_without_search_service() {
        let mut session = ReplSession::new();
        let (_, output) = session.process_line(":ir rust", None);
        assert!(output.contains("Capturing rust source"), "{output}");
        assert!(
            session
                .process_line("fn greet(name: &str) {", None)
                .1
                .is_empty()
        );
        assert!(
            session
                .process_line("    println!(\"{name}\");", None)
                .1
                .is_empty()
        );
        assert!(session.process_line("}", None).1.is_empty());

        let (_, output) = session.process_line(":end", None);
        assert!(output.contains("Rune IR (rust):"), "{output}");
        assert!(output.contains("(function"), "{output}");
        assert!(output.contains(":name \"greet\""), "{output}");
        assert!(
            output.contains("Starter RQL:\n(function :name \"greet\")"),
            "{output}"
        );
        assert!(!output.contains("function_item"), "{output}");
    }

    #[test]
    fn rune_ir_capture_preserves_leading_blank_lines_and_ranges() {
        let mut session = ReplSession::new();
        session.process_line(":ir rust", None);
        session.process_line("", None);
        session.process_line("fn f() {}", None);

        let (_, output) = session.process_line(":end", None);
        assert!(output.contains("(function :range (1 10)"), "{output}");
    }

    #[test]
    fn rune_ir_terminal_output_escapes_directional_controls() {
        let mut session = ReplSession::new();
        session.process_line(":ir rust", None);
        session.process_line("fn f() { let value = \"safe\u{202e}evil\"; }", None);

        let (_, output) = session.process_line(":end", None);
        assert!(!output.contains('\u{202e}'), "{output:?}");
        assert!(output.contains("\\u{202e}"), "{output:?}");
    }

    #[test]
    fn rune_ir_source_lines_are_excluded_from_history() {
        let capture_mode = Arc::new(AtomicBool::new(false));
        let inner = FileBackedHistory::new(10).unwrap();
        let mut history = CaptureFilteringHistory::new(inner, Arc::clone(&capture_mode));
        history
            .save(HistoryItem::from_command_line(":ir rust"))
            .unwrap();
        capture_mode.store(true, Ordering::Relaxed);
        history
            .save(HistoryItem::from_command_line("let token = \"secret\";"))
            .unwrap();

        let entries = history
            .search(SearchQuery::everything(
                reedline::SearchDirection::Forward,
                None,
            ))
            .unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].command_line, ":ir rust");
    }

    #[test]
    fn rune_ir_languages_include_tsx_parser_flavor() {
        assert!(languages_text().lines().any(|label| label == "tsx"));
        assert!(doc_text("tsx").contains("TypeScript source containing JSX"));
        let mut completer = ReplCompleter::new();
        assert!(
            completer
                .complete("tsx", 3)
                .iter()
                .any(|suggestion| suggestion.value == "tsx")
        );
    }

    #[test]
    fn code_query_repl_rune_ir_errors_are_actionable() {
        let mut session = ReplSession::new();
        let (_, output) = session.process_line(":ir", None);
        assert!(output.contains("usage: :ir <language>"), "{output}");

        let (_, output) = session.process_line(":ir brainfuck", None);
        assert!(output.contains("unsupported Rune IR language"), "{output}");

        session.process_line(":ir python", None);
        let (_, output) = session.process_line(":end", None);
        assert!(output.contains("source is empty"), "{output}");
    }

    #[test]
    fn rune_ir_capture_treats_colon_commands_as_source_until_end() {
        let mut session = ReplSession::new();
        session.process_line(":ir python", None);
        session.process_line(":run", None);
        assert!(session.is_capturing_rune_ir());
        let (_, output) = session.process_line(":end", None);
        assert!(!output.contains("No search service"), "{output}");
    }

    #[test]
    fn rune_ir_capture_does_not_initialize_lazy_search_service() {
        let mut session = ReplSession::new();
        let mut service = LazySearchService::new(PathBuf::from("unused"));
        process_line_with_lazy_service(&mut session, ":ir rust", &mut service).unwrap();
        process_line_with_lazy_service(&mut session, "fn demo() {}", &mut service).unwrap();
        let (_, output) =
            process_line_with_lazy_service(&mut session, ":end", &mut service).unwrap();
        assert!(output.contains("Rune IR (rust):"), "{output}");
        assert!(service.service.is_none());
    }

    #[test]
    fn rune_ir_capture_rejects_oversized_input_and_resets() {
        let mut session = ReplSession::new();
        session.process_line(":ir rust", None);
        let oversized = "x".repeat(RuneIrLimits::default().max_input_bytes + 1);
        let (_, output) = session.process_line(&oversized, None);

        assert!(output.contains("input limit"), "{output}");
        assert!(output.contains("capture cancelled"), "{output}");
        assert!(!session.is_capturing_rune_ir());
        assert!(!session.rune_ir_capture_mode.load(Ordering::Relaxed));
    }

    #[test]
    fn rune_ir_capture_bypasses_query_delimiter_validation() {
        let capture_mode = Arc::new(AtomicBool::new(false));
        let validator = ReplValidator {
            rune_ir_capture_mode: Arc::clone(&capture_mode),
        };
        let mut session = ReplSession::with_capture_mode(false, capture_mode);

        assert!(matches!(
            validator.validate("fn broken("),
            ValidationResult::Incomplete
        ));
        session.process_line(":ir rust", None);
        assert!(matches!(
            validator.validate("fn broken("),
            ValidationResult::Complete
        ));
        session.process_line("fn broken(", None);
        assert!(matches!(
            validator.validate(":end"),
            ValidationResult::Complete
        ));
        let (_, output) = session.process_line(":end", None);
        assert!(!session.is_capturing_rune_ir());
        assert!(
            !output.is_empty(),
            "capture should finish with a result or actionable error"
        );
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
            completer
                .complete("comm", 4)
                .iter()
                .any(|suggestion| suggestion.value == "comments")
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
        let validator = ReplValidator {
            rune_ir_capture_mode: Arc::new(AtomicBool::new(false)),
        };
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
        let matched = CodeQueryMatch {
            path: "editors/vscode/src/provisioning.ts".to_string(),
            language: "typescript",
            kind: "function",
            start_line: 259,
            end_line: 269,
            text:
                "async function probeBifrostVersion(binaryPath: string): Promise<VersionProbe> {…"
                    .to_string(),
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
        };
        let output = render_code_query_repl_output(
            &CodeQueryResult {
                results: vec![CodeQueryResultItem {
                    value: CodeQueryResultValue::StructuralMatch {
                        value: matched.clone(),
                    },
                    provenance: Vec::new(),
                    provenance_truncated: false,
                }],
                truncated: false,
                diagnostics: Vec::new(),
            },
            false,
        );

        assert!(output.contains("1 result"), "{output}");
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
        let matched = CodeQueryMatch {
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
        };
        let output = render_code_query_repl_output(
            &CodeQueryResult {
                results: vec![CodeQueryResultItem {
                    value: CodeQueryResultValue::StructuralMatch {
                        value: matched.clone(),
                    },
                    provenance: Vec::new(),
                    provenance_truncated: false,
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
