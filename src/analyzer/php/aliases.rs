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

#[derive(Debug, Clone)]
pub struct PhpFileContext {
    pub namespace: String,
    pub aliases: PhpUseAliases,
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

pub fn resolve_php_type(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    let first = raw.split('|').next().unwrap_or(raw).trim();
    if first.is_empty() || matches!(first, "self" | "static" | "parent") {
        return None;
    }
    if first.starts_with('\\') {
        return Some(php_namespace_to_fq(first));
    }
    let normalized = php_namespace_to_fq(first);
    let local = normalized.split('.').next().unwrap_or(normalized.as_str());
    if let Some(imported) = ctx.aliases.type_aliases.get(local) {
        if normalized == local {
            return Some(imported.clone());
        }
        let suffix = normalized
            .strip_prefix(local)
            .unwrap_or("")
            .trim_start_matches('.');
        return Some(if suffix.is_empty() {
            imported.clone()
        } else {
            format!("{imported}.{suffix}")
        });
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(crate) fn resolve_php_function(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(php_namespace_to_fq(raw));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.function_aliases.get(&normalized) {
        return Some(imported.clone());
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(crate) fn resolve_php_constant(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(module_constant_fq(&php_namespace_to_fq(raw)));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.const_aliases.get(&normalized) {
        return Some(module_constant_fq(imported));
    }
    Some(join_namespace(
        &ctx.namespace,
        &format!("_module_.{normalized}"),
    ))
}

fn module_constant_fq(fq_name: &str) -> String {
    if fq_name.contains("._module_.") {
        return fq_name.to_string();
    }
    let public = public_php_fq_name(fq_name);
    if let Some((namespace, name)) = public.rsplit_once('.') {
        format!("{namespace}._module_.{name}")
    } else {
        format!("_module_.{public}")
    }
}

fn public_php_fq_name(fq_name: &str) -> String {
    fq_name.replace("._module_.", ".")
}

fn join_namespace(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        namespace.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}
