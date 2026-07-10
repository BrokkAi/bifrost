use super::ir::{CodeQuery, Pattern, StringPredicate};
use crate::analyzer::structural::kinds::{NormalizedKind, Role};
use serde_json::{Map, Value, json};

impl CodeQuery {
    /// The canonical JSON form of this query. Used by `--print-json` style
    /// debugging and by tests asserting that both frontends parse to the same
    /// query (`parse(json).to_canonical_json() == parse(sexp).to_canonical_json()`).
    pub fn to_canonical_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("schema_version".to_string(), json!(self.schema_version));
        if !self.where_globs.is_empty() {
            object.insert(
                "where".to_string(),
                Value::Array(
                    self.where_globs
                        .iter()
                        .map(|glob| Value::String(glob.as_str().to_string()))
                        .collect(),
                ),
            );
        }
        if !self.languages.is_empty() {
            object.insert(
                "languages".to_string(),
                Value::Array(
                    self.languages
                        .iter()
                        .map(|language| Value::String(language.config_label().to_string()))
                        .collect(),
                ),
            );
        }
        object.insert("match".to_string(), pattern_to_json(&self.root));
        if let Some(pattern) = &self.inside {
            object.insert("inside".to_string(), pattern_to_json(pattern));
        }
        if let Some(pattern) = &self.not_inside {
            object.insert("not_inside".to_string(), pattern_to_json(pattern));
        }
        object.insert("limit".to_string(), json!(self.limit));
        object.insert(
            "result_detail".to_string(),
            json!(self.result_detail.label()),
        );
        Value::Object(object)
    }
}

fn kind_list_to_json(kinds: &[NormalizedKind]) -> Value {
    if kinds.len() == 1 {
        json!(kinds[0].label())
    } else {
        Value::Array(kinds.iter().map(|kind| json!(kind.label())).collect())
    }
}

fn pattern_to_json(pattern: &Pattern) -> Value {
    let mut object = Map::new();
    if !pattern.kinds.is_empty() {
        object.insert("kind".to_string(), kind_list_to_json(&pattern.kinds));
    }
    if !pattern.not_kinds.is_empty() {
        object.insert(
            "not_kind".to_string(),
            kind_list_to_json(&pattern.not_kinds),
        );
    }
    if let Some(predicate) = &pattern.name {
        object.insert("name".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(predicate) = &pattern.text {
        object.insert("text".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(capture) = &pattern.capture {
        object.insert("capture".to_string(), json!(capture));
    }
    if let Some(sub) = &pattern.has {
        object.insert("has".to_string(), pattern_to_json(sub));
    }
    if let Some(sub) = &pattern.not_has {
        object.insert("not_has".to_string(), pattern_to_json(sub));
    }
    for &role in Role::single_target_roles() {
        if let Some(sub) = pattern.single_role_pattern(role) {
            object.insert(role.label().to_string(), pattern_to_json(sub));
        }
    }
    for &role in Role::list_target_roles() {
        let patterns = pattern.list_role_patterns(role);
        if !patterns.is_empty() {
            object.insert(
                role.label().to_string(),
                Value::Array(patterns.iter().map(pattern_to_json).collect()),
            );
        }
    }
    if !pattern.kwargs.is_empty() {
        let mut kwargs = Map::new();
        for (keyword, sub) in &pattern.kwargs {
            kwargs.insert(keyword.clone(), pattern_to_json(sub));
        }
        object.insert(Role::Kwarg.label().to_string(), Value::Object(kwargs));
    }
    Value::Object(object)
}

fn string_predicate_to_json(predicate: &StringPredicate) -> Value {
    match predicate {
        StringPredicate::Exact(text) => json!(text),
        StringPredicate::Regex(regex) => json!({ "regex": regex.as_str() }),
    }
}
