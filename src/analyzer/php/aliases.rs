use crate::hash::HashMap;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpUseAliases {
    pub type_aliases: HashMap<String, String>,
    pub function_aliases: HashMap<String, String>,
    pub const_aliases: HashMap<String, String>,
}

impl PhpUseAliases {
    pub(super) fn extend(&mut self, other: Self) {
        self.type_aliases.extend(other.type_aliases);
        self.function_aliases.extend(other.function_aliases);
        self.const_aliases.extend(other.const_aliases);
    }

    pub fn merged(&self) -> HashMap<String, String> {
        let mut aliases = self.type_aliases.clone();
        aliases.extend(self.function_aliases.clone());
        aliases.extend(self.const_aliases.clone());
        aliases
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhpUseKind {
    Type,
    Function,
    Const,
}

static PHP_USE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^use\s+[^;]+;").expect("valid PHP use regex"));

pub fn parse_php_use_aliases_from_source(source: &str) -> PhpUseAliases {
    let mut aliases = PhpUseAliases::default();
    for matched in PHP_USE_RE.find_iter(source) {
        aliases.extend(parse_php_use_aliases_by_kind(matched.as_str()));
    }
    aliases
}

pub fn parse_php_use_aliases_by_kind(raw: &str) -> PhpUseAliases {
    let mut text = raw.trim().trim_end_matches(';').trim();
    let Some(rest) = text.strip_prefix("use ") else {
        return PhpUseAliases::default();
    };
    text = rest.trim();

    let (default_kind, text) = if let Some(rest) = text.strip_prefix("function ") {
        (PhpUseKind::Function, rest.trim())
    } else if let Some(rest) = text.strip_prefix("const ") {
        (PhpUseKind::Const, rest.trim())
    } else {
        (PhpUseKind::Type, text)
    };

    let mut aliases = PhpUseAliases::default();
    if text.is_empty() {
        return aliases;
    }

    if let Some((prefix, group)) = text.split_once('{') {
        let prefix = prefix.trim().trim_end_matches('\\');
        let group = group.trim_end_matches('}').trim();
        for part in group.split(',') {
            add_php_use_alias(prefix, part.trim(), default_kind, &mut aliases);
        }
        return aliases;
    }

    add_php_use_alias("", text, default_kind, &mut aliases);
    aliases
}

pub fn parse_php_use_aliases(raw: &str) -> HashMap<String, String> {
    parse_php_use_aliases_by_kind(raw).merged()
}

fn add_php_use_alias(
    prefix: &str,
    raw_part: &str,
    default_kind: PhpUseKind,
    aliases: &mut PhpUseAliases,
) {
    if raw_part.is_empty() {
        return;
    }
    let (kind, raw_part) = if let Some(rest) = raw_part.strip_prefix("function ") {
        (PhpUseKind::Function, rest.trim())
    } else if let Some(rest) = raw_part.strip_prefix("const ") {
        (PhpUseKind::Const, rest.trim())
    } else {
        (default_kind, raw_part)
    };
    let (path, alias) = split_php_use_alias(raw_part);
    let full_path = if prefix.is_empty() {
        path
    } else {
        format!("{prefix}\\{path}")
    };
    let fq = php_namespace_to_fq(&full_path);
    if fq.is_empty() {
        return;
    }
    let local = alias.unwrap_or_else(|| fq.rsplit('.').next().unwrap_or(fq.as_str()).to_string());
    match kind {
        PhpUseKind::Type => aliases.type_aliases.insert(local, fq),
        PhpUseKind::Function => aliases.function_aliases.insert(local, fq),
        PhpUseKind::Const => aliases.const_aliases.insert(local, fq),
    };
}

fn split_php_use_alias(raw_part: &str) -> (String, Option<String>) {
    let normalized = raw_part.trim();
    let lower = normalized.to_ascii_lowercase();
    if let Some(index) = lower.rfind(" as ") {
        let path = normalized[..index].trim().to_string();
        let alias = normalized[index + 4..].trim().to_string();
        return (path, (!alias.is_empty()).then_some(alias));
    }
    (normalized.to_string(), None)
}

pub fn php_namespace_to_fq(name: &str) -> String {
    name.trim()
        .trim_start_matches('\\')
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}
