use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::hash::{HashMap, HashSet};
use crate::path_normalization::NormalizePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Language {
    None,
    Java,
    Go,
    Cpp,
    JavaScript,
    TypeScript,
    Python,
    Rust,
    Php,
    Scala,
    CSharp,
    Ruby,
    Kotlin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RubyMethodDispatchMode {
    Instance,
    Singleton,
    ModuleFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalaExportSelector {
    Wildcard,
    GivenWildcard,
    Named {
        source_name: String,
        visible_name: Option<String>,
    },
}

/// One Scala `export` clause recorded against the template that owns it.
///
/// Scala-shaped by content: the selector vocabulary is the language's own, so
/// the name stays as it is rather than becoming a false generalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalaExportInfo {
    pub owner_path: Vec<String>,
    pub selectors: Vec<ScalaExportSelector>,
    pub declaration_start_byte: usize,
}

impl Language {
    pub const ANALYZABLE: [Self; 12] = [
        Language::Java,
        Language::Go,
        Language::Cpp,
        Language::JavaScript,
        Language::TypeScript,
        Language::Python,
        Language::Rust,
        Language::Php,
        Language::Scala,
        Language::CSharp,
        Language::Ruby,
        Language::Kotlin,
    ];

    pub fn config_label(self) -> &'static str {
        match self {
            Language::None => "none",
            Language::Java => "java",
            Language::Go => "go",
            Language::Cpp => "cpp",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Python => "python",
            Language::Rust => "rust",
            Language::Php => "php",
            Language::Scala => "scala",
            Language::CSharp => "csharp",
            Language::Ruby => "ruby",
            Language::Kotlin => "kotlin",
        }
    }

    /// Additional user-facing labels accepted by [`Self::from_config_label`].
    pub fn config_label_aliases(self) -> &'static [&'static str] {
        match self {
            Language::Cpp => &["c++"],
            Language::CSharp => &["c#"],
            _ => &[],
        }
    }

    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Language::None => &[],
            Language::Java => &["java"],
            Language::Go => &["go"],
            Language::Cpp => &["c", "cc", "cpp", "cxx", "h", "hpp", "hh", "hxx"],
            Language::JavaScript => &["js", "mjs", "cjs", "jsx"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Python => &["py"],
            Language::Rust => &["rs"],
            Language::Php => &["php"],
            Language::Scala => &["scala"],
            Language::CSharp => &["cs"],
            Language::Ruby => &["rb"],
            Language::Kotlin => &["kt", "kts"],
        }
    }

    pub fn reference_only_sibling_extensions(self) -> &'static [&'static str] {
        match self {
            Language::CSharp => &["razor", "cshtml"],
            Language::JavaScript | Language::TypeScript => &["vue", "svelte"],
            _ => &[],
        }
    }

    pub fn is_source_extension(extension: &str) -> bool {
        let normalized = extension.trim_start_matches('.').to_ascii_lowercase();
        Self::ANALYZABLE.iter().any(|language| {
            language.extensions().contains(&normalized.as_str())
                || language
                    .reference_only_sibling_extensions()
                    .contains(&normalized.as_str())
        })
    }

    pub fn from_extension(extension: &str) -> Self {
        let normalized = extension.trim_start_matches('.').to_ascii_lowercase();
        for language in Self::ANALYZABLE {
            if language.extensions().contains(&normalized.as_str()) {
                return language;
            }
        }
        Language::None
    }

    pub fn from_config_label(input: &str) -> Option<Self> {
        let normalized = input
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        Self::ANALYZABLE.into_iter().find(|&language| {
            normalized == language.config_label()
                || language
                    .config_label_aliases()
                    .contains(&normalized.as_str())
                || language.extensions().contains(&normalized.as_str())
        })
    }
}

/// A source language plus the parser dialect needed to interpret one file.
///
/// Most languages have one grammar. TypeScript is the exception because `.ts`
/// and `.tsx` files use distinct tree-sitter grammars while sharing the same
/// normalized language adapter.
///
/// Resolving a dialect to an actual `tree_sitter::Language` needs the grammar
/// registry, which is `brokk-bifrost-analysis` machinery: see
/// `crate::analyzer::parser_language_for_dialect` there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LanguageDialect {
    Standard(Language),
    TypeScriptTsx,
}

impl LanguageDialect {
    /// Parse a user-facing language or dialect label.
    pub fn from_config_label(label: &str) -> Option<Self> {
        let normalized = label
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        if matches!(
            normalized.as_str(),
            "tsx" | "typescriptreact" | "typescripttsx"
        ) {
            return Some(Self::TypeScriptTsx);
        }
        Language::from_config_label(label).map(Self::Standard)
    }

    /// Select the parser dialect used by the indexed analyzer for `path`.
    pub fn for_path(language: Language, path: &Path) -> Self {
        if language == Language::TypeScript
            && path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tsx"))
        {
            Self::TypeScriptTsx
        } else {
            Self::Standard(language)
        }
    }

    pub const fn language(self) -> Language {
        match self {
            Self::Standard(language) => language,
            Self::TypeScriptTsx => Language::TypeScript,
        }
    }

    /// Canonical durable identity label. Unlike [`Self::config_label`], this
    /// makes the TypeScript language explicit rather than using the `tsx`
    /// shorthand.
    pub fn stable_label(self) -> &'static str {
        match self {
            Self::Standard(language) => language.config_label(),
            Self::TypeScriptTsx => "typescript-tsx",
        }
    }

    /// Short user-facing configuration label retained by Rune IR and the CLI.
    pub fn config_label(self) -> &'static str {
        match self {
            Self::Standard(language) => language.config_label(),
            Self::TypeScriptTsx => "tsx",
        }
    }

    pub fn config_labels() -> impl Iterator<Item = &'static str> {
        Language::ANALYZABLE
            .iter()
            .map(|language| language.config_label())
            .chain(std::iter::once("tsx"))
    }
}

impl From<Language> for LanguageDialect {
    fn from(language: Language) -> Self {
        Self::Standard(language)
    }
}

impl fmt::Display for LanguageDialect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_label())
    }
}

/// Coarse declaration categories used across analyzers, lookup, usages, and
/// serialized state. Keep this enum lean and language-agnostic: prefer mapping
/// syntax-specific distinctions onto an existing high-level kind unless callers
/// must handle the unit with genuinely different semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CodeUnitType {
    /// Type-like declarations: classes, interfaces, abstract classes, structs,
    /// traits, protocols, enums, unions, aliases, and language equivalents.
    /// Use `Class` for declarations whose primary role is defining a named
    /// type or member namespace, even when the language uses another keyword.
    Class,
    /// Runtime-invocable executable units: free functions, methods, closures,
    /// lambdas, and language-specific equivalents. These share a callable body
    /// model even when their declaration syntax differs.
    Function,
    /// Addressable data members and named values: fields, properties,
    /// constants, enum cases, and similar slots. For object-property-heavy
    /// languages, classify by the declared value's role: JavaScript/TypeScript
    /// `{ run() {} }` and `{ run: () => {} }` are `Function`, while `{ enabled:
    /// true }` is `Field`; PHP methods are `Function`, while properties and
    /// constants are `Field`.
    Field,
    /// Named importable or namespace-like containers. Examples currently
    /// emitted as `Module` include C++ namespaces, Java package units, Python
    /// modules, Rust modules, Ruby modules, and file-level JavaScript/TypeScript
    /// modules. Do not assume every language namespace is a `Module`: C#
    /// namespaces are package scope for contained declarations, and TypeScript
    /// `namespace`/`module` declarations are currently class-like CodeUnits.
    Module,
    /// Compile-time invocable units such as Rust `macro_rules!` and C/C++
    /// preprocessor macros. Keep these distinct from `Function` because their
    /// bodies are token/template rules, their "calls" expand inline before
    /// ordinary semantic analysis, and resolving them does not imply a runtime
    /// call edge.
    Macro,
    FileScope,
}

impl CodeUnitType {
    /// Lowercase English label suitable for inline use in human-facing
    /// report sentences (e.g. "large class spans 423 lines"). Distinct from
    /// the on-disk persistence label so the two evolve independently.
    pub fn display_lowercase(&self) -> &'static str {
        match self {
            CodeUnitType::Class => "class",
            CodeUnitType::Function => "function",
            CodeUnitType::Field => "field",
            CodeUnitType::Module => "module",
            CodeUnitType::Macro => "macro",
            CodeUnitType::FileScope => "file scope",
        }
    }

    pub fn is_callable_kind(&self) -> bool {
        matches!(self, CodeUnitType::Function)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParameterMetadata {
    label: String,
    start_byte: usize,
    end_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallableArity {
    required: usize,
    total: usize,
    repeated: bool,
}

impl CallableArity {
    pub fn new(required: usize, total: usize, repeated: bool) -> Self {
        Self {
            required,
            total,
            repeated,
        }
    }

    pub fn exact(arity: usize) -> Self {
        Self::new(arity, arity, false)
    }

    pub fn accepts(self, arity: usize) -> bool {
        arity >= self.required && (self.repeated || arity <= self.total)
    }

    pub fn total(self) -> usize {
        self.total
    }

    pub fn is_repeated(self) -> bool {
        self.repeated
    }
}

/// What a workspace-wide usage-facts index knows about one callable
/// declaration: how many arguments it accepts, in both the legacy flat and the
/// required/total/repeated spelling, and the fq name of the type it returns.
///
/// Pure data over [`CallableArity`], so it sits beside it rather than in the
/// analysis-side index that builds it; the language crates that read the facts
/// through a narrow accessor need the shape, not the index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallableFacts {
    pub arity: Option<usize>,
    pub callable_arity: Option<CallableArity>,
    pub return_type_fqn: Option<String>,
    pub is_function: bool,
}

impl ParameterMetadata {
    pub fn new(label: impl Into<String>, start_byte: usize, end_byte: usize) -> Self {
        Self {
            label: label.into(),
            start_byte,
            end_byte,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn start_byte(&self) -> usize {
        self.start_byte
    }

    pub fn end_byte(&self) -> usize {
        self.end_byte
    }
}

/// Linkage carried by callable declaration metadata when the language makes
/// cross-file symbol identity explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallableLinkage {
    External,
    Internal,
}

/// Whether one callable declaration proves that runtime dispatch is closed.
///
/// Signature metadata carries this declaration-side fact so bounded query
/// layers can reason about dispatch without reparsing or rematerializing the
/// target file. Languages that have not published the fact leave it absent,
/// which callers must treat conservatively.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DispatchExtensibility {
    #[default]
    Open,
    Closed,
}

impl DispatchExtensibility {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignatureMetadata {
    label: String,
    parameters: Vec<ParameterMetadata>,
    #[serde(default)]
    return_type_text: Option<String>,
    #[serde(default)]
    return_type_identity: Option<StructuredTypeIdentity>,
    #[serde(default)]
    declaration_only: bool,
    #[serde(default)]
    callable_arity: Option<CallableArity>,
    #[serde(default)]
    type_parameters: Vec<String>,
    #[serde(default)]
    bare_return_type_parameter: Option<String>,
    #[serde(default)]
    callable_linkage: Option<CallableLinkage>,
    #[serde(default)]
    dispatch_extensibility: Option<DispatchExtensibility>,
    #[serde(default)]
    extension_receiver_type: Option<String>,
    #[serde(default)]
    extension_receiver_type_identity: Option<StructuredTypeIdentity>,
    #[serde(default)]
    extension_receiver_is_unconstrained_type_parameter: bool,
    #[serde(default)]
    field_is_static: bool,
    #[serde(default)]
    field_is_final: bool,
    /// Whether this class-like declaration is a Kotlin `companion object`.
    ///
    /// A companion and an ordinary nested `object` are both nested classes, and
    /// the `Companion` default name is a name-resolution rule a source file is
    /// free to override, so companion-ness cannot be read off the declaration's
    /// identity. Publishing it here is what lets a consumer ask "are this
    /// owner's members reachable through the enclosing class's own name?"
    /// without re-parsing the declaring file — the question the whole-workspace
    /// usage-edge builder asks once per callee owner.
    #[serde(default)]
    companion_object: bool,
}

/// A parser-derived nominal type name, including the lexical scope in which an
/// unqualified path was written. Keeping these components structured lets
/// bounded consumers resolve persisted signatures without reparsing rendered
/// source text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct StructuredTypeName {
    path: Vec<String>,
    lexical_scope: Vec<String>,
    absolute: bool,
}

const MAX_STRUCTURED_TYPE_NAME_COMPONENTS: usize = 1_024;
const MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES: usize = 1 << 20;
pub(crate) const MAX_STRUCTURED_TYPE_IDENTITY_NODES: usize = 20_000;
const MAX_STRUCTURED_TYPE_IDENTITY_EDGES: usize = 40_000;
pub const MAX_SIGNATURE_METADATA_BLOB_BYTES: usize = 8 << 20;

struct BoundedStructuredTypeNameComponentsSeed {
    max_components: usize,
    max_string_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedStructuredTypeNameComponentsSeed {
    type Value = Vec<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ComponentsVisitor {
            max_components: usize,
            max_string_bytes: usize,
        }

        impl<'de> Visitor<'de> for ComponentsVisitor {
            type Value = Vec<String>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {} structured type-name components totaling at most {} bytes",
                    self.max_components, self.max_string_bytes
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > self.max_components)
                {
                    return Err(serde::de::Error::custom(
                        "structured type name exceeds the component cap",
                    ));
                }
                let mut components = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or_default()
                        .min(self.max_components),
                );
                let mut remaining_string_bytes = self.max_string_bytes;
                loop {
                    if components.len() == self.max_components {
                        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(
                                "structured type name exceeds the component cap",
                            ));
                        }
                        break;
                    }
                    let component =
                        sequence.next_element_seed(BoundedStructuredTypeStringSeed {
                            max_bytes: remaining_string_bytes,
                        })?;
                    let Some(component) = component else {
                        break;
                    };
                    remaining_string_bytes = remaining_string_bytes
                        .checked_sub(component.len())
                        .ok_or_else(|| {
                            serde::de::Error::custom(
                                "structured type name exceeds the string-byte cap",
                            )
                        })?;
                    components.push(component);
                }
                Ok(components)
            }
        }

        deserializer.deserialize_seq(ComponentsVisitor {
            max_components: self.max_components,
            max_string_bytes: self.max_string_bytes,
        })
    }
}

struct BoundedStructuredTypeStringSeed {
    max_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedStructuredTypeStringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringVisitor {
            max_bytes: usize,
        }

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a structured type-name component no longer than {} bytes",
                    self.max_bytes
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > self.max_bytes {
                    return Err(E::custom(
                        "structured type name exceeds the string-byte cap",
                    ));
                }
                Ok(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > self.max_bytes {
                    return Err(E::custom(
                        "structured type name exceeds the string-byte cap",
                    ));
                }
                Ok(value)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > self.max_bytes)
                {
                    return Err(serde::de::Error::custom(
                        "structured type name exceeds the string-byte cap",
                    ));
                }
                let mut bytes = Vec::with_capacity(
                    sequence.size_hint().unwrap_or_default().min(self.max_bytes),
                );
                while let Some(byte) = sequence.next_element()? {
                    if bytes.len() == self.max_bytes {
                        return Err(serde::de::Error::custom(
                            "structured type name exceeds the string-byte cap",
                        ));
                    }
                    bytes.push(byte);
                }
                String::from_utf8(bytes).map_err(serde::de::Error::custom)
            }
        }

        let visitor = StringVisitor {
            max_bytes: self.max_bytes,
        };
        if deserializer.is_human_readable() {
            deserializer.deserialize_string(visitor)
        } else {
            // Bincode encodes strings and byte sequences identically. Reading
            // the component as a sequence exposes its length hint before a
            // buffer is allocated while preserving the existing wire format.
            deserializer.deserialize_seq(visitor)
        }
    }
}

enum StructuredTypeNameField {
    Path,
    LexicalScope,
    Absolute,
}

impl<'de> Deserialize<'de> for StructuredTypeNameField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldVisitor;

        impl Visitor<'_> for FieldVisitor {
            type Value = StructuredTypeNameField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a structured type-name field")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "path" => Ok(StructuredTypeNameField::Path),
                    "lexical_scope" => Ok(StructuredTypeNameField::LexicalScope),
                    "absolute" => Ok(StructuredTypeNameField::Absolute),
                    _ => Err(E::unknown_field(
                        value,
                        &["path", "lexical_scope", "absolute"],
                    )),
                }
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

impl<'de> Deserialize<'de> for StructuredTypeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NameVisitor;

        impl<'de> Visitor<'de> for NameVisitor {
            type Value = StructuredTypeName;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded structured type name")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let path = sequence
                    .next_element_seed(BoundedStructuredTypeNameComponentsSeed {
                        max_components: MAX_STRUCTURED_TYPE_NAME_COMPONENTS,
                        max_string_bytes: MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES,
                    })?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let remaining_components = MAX_STRUCTURED_TYPE_NAME_COMPONENTS
                    .checked_sub(path.len())
                    .ok_or_else(|| {
                        serde::de::Error::custom("structured type name exceeds the component cap")
                    })?;
                let path_string_bytes = path.iter().try_fold(0usize, |total, component| {
                    total.checked_add(component.len())
                });
                let remaining_string_bytes = path_string_bytes
                    .and_then(|used| MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES.checked_sub(used))
                    .ok_or_else(|| {
                        serde::de::Error::custom("structured type name exceeds the string-byte cap")
                    })?;
                let lexical_scope = sequence
                    .next_element_seed(BoundedStructuredTypeNameComponentsSeed {
                        max_components: remaining_components,
                        max_string_bytes: remaining_string_bytes,
                    })?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let absolute = sequence
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                StructuredTypeName::new(path, lexical_scope, absolute)
                    .ok_or_else(|| serde::de::Error::custom("invalid structured type name"))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut path = None;
                let mut lexical_scope = None;
                let mut absolute = None;
                while let Some(field) = map.next_key()? {
                    match field {
                        StructuredTypeNameField::Path => {
                            if path.is_some() {
                                return Err(serde::de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value_seed(
                                BoundedStructuredTypeNameComponentsSeed {
                                    max_components: MAX_STRUCTURED_TYPE_NAME_COMPONENTS,
                                    max_string_bytes: MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES,
                                },
                            )?);
                        }
                        StructuredTypeNameField::LexicalScope => {
                            if lexical_scope.is_some() {
                                return Err(serde::de::Error::duplicate_field("lexical_scope"));
                            }
                            lexical_scope = Some(map.next_value_seed(
                                BoundedStructuredTypeNameComponentsSeed {
                                    max_components: MAX_STRUCTURED_TYPE_NAME_COMPONENTS,
                                    max_string_bytes: MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES,
                                },
                            )?);
                        }
                        StructuredTypeNameField::Absolute => {
                            if absolute.is_some() {
                                return Err(serde::de::Error::duplicate_field("absolute"));
                            }
                            absolute = Some(map.next_value()?);
                        }
                    }
                }
                let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                let lexical_scope = lexical_scope
                    .ok_or_else(|| serde::de::Error::missing_field("lexical_scope"))?;
                let absolute =
                    absolute.ok_or_else(|| serde::de::Error::missing_field("absolute"))?;
                StructuredTypeName::new(path, lexical_scope, absolute)
                    .ok_or_else(|| serde::de::Error::custom("invalid structured type name"))
            }
        }

        deserializer.deserialize_struct(
            "StructuredTypeName",
            &["path", "lexical_scope", "absolute"],
            NameVisitor,
        )
    }
}

impl StructuredTypeName {
    pub fn new(path: Vec<String>, lexical_scope: Vec<String>, absolute: bool) -> Option<Self> {
        let name = Self {
            path,
            lexical_scope,
            absolute,
        };
        if !name.is_valid() {
            return None;
        }
        Some(name)
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    pub fn lexical_scope(&self) -> &[String] {
        &self.lexical_scope
    }

    pub const fn is_absolute(&self) -> bool {
        self.absolute
    }

    fn is_valid(&self) -> bool {
        let Some(component_count) = self.path.len().checked_add(self.lexical_scope.len()) else {
            return false;
        };
        let Some(string_bytes) = self
            .path
            .iter()
            .chain(&self.lexical_scope)
            .try_fold(0usize, |total, component| {
                total.checked_add(component.len())
            })
        else {
            return false;
        };
        !self.path.is_empty()
            && !self
                .path
                .iter()
                .chain(&self.lexical_scope)
                .any(String::is_empty)
            && component_count <= MAX_STRUCTURED_TYPE_NAME_COMPONENTS
            && string_bytes <= MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES
    }
}

/// Stable index into a [`StructuredTypeIdentity`] arena.
///
/// Nodes are appended after their children, so every edge points to a smaller
/// index. That invariant makes malformed persisted values fail closed and
/// keeps every traversal iterative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructuredTypeNodeId(u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
enum StructuredTypeNode {
    Named(StructuredTypeName),
    Pointer(StructuredTypeNodeId),
    Reference(StructuredTypeNodeId),
    Array(StructuredTypeNodeId),
    Slice(StructuredTypeNodeId),
    Map {
        key: StructuredTypeNodeId,
        value: StructuredTypeNodeId,
    },
    Generic {
        base: StructuredTypeNodeId,
        arguments: Vec<StructuredTypeNodeId>,
    },
}

#[derive(Deserialize)]
enum StructuredTypeNodeWire {
    Named(StructuredTypeName),
    Pointer(StructuredTypeNodeId),
    Reference(StructuredTypeNodeId),
    Array(StructuredTypeNodeId),
    Slice(StructuredTypeNodeId),
    Map {
        key: StructuredTypeNodeId,
        value: StructuredTypeNodeId,
    },
    Generic {
        base: StructuredTypeNodeId,
        arguments: BoundedStructuredTypeNodeIds,
    },
}

struct BoundedStructuredTypeNodeIds(Vec<StructuredTypeNodeId>);

impl<'de> Deserialize<'de> for BoundedStructuredTypeNodeIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NodeIdsVisitor;

        impl<'de> Visitor<'de> for NodeIdsVisitor {
            type Value = BoundedStructuredTypeNodeIds;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_STRUCTURED_TYPE_IDENTITY_EDGES} generic type arguments"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > MAX_STRUCTURED_TYPE_IDENTITY_EDGES)
                {
                    return Err(serde::de::Error::custom(
                        "structured type identity exceeds the edge cap",
                    ));
                }
                let mut ids = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or_default()
                        .min(MAX_STRUCTURED_TYPE_IDENTITY_EDGES),
                );
                while let Some(id) = sequence.next_element()? {
                    if ids.len() == MAX_STRUCTURED_TYPE_IDENTITY_EDGES {
                        return Err(serde::de::Error::custom(
                            "structured type identity exceeds the edge cap",
                        ));
                    }
                    ids.push(id);
                }
                Ok(BoundedStructuredTypeNodeIds(ids))
            }
        }

        deserializer.deserialize_seq(NodeIdsVisitor)
    }
}

impl<'de> Deserialize<'de> for StructuredTypeNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match StructuredTypeNodeWire::deserialize(deserializer)? {
            StructuredTypeNodeWire::Named(name) => Self::Named(name),
            StructuredTypeNodeWire::Pointer(inner) => Self::Pointer(inner),
            StructuredTypeNodeWire::Reference(inner) => Self::Reference(inner),
            StructuredTypeNodeWire::Array(inner) => Self::Array(inner),
            StructuredTypeNodeWire::Slice(inner) => Self::Slice(inner),
            StructuredTypeNodeWire::Map { key, value } => Self::Map { key, value },
            StructuredTypeNodeWire::Generic { base, arguments } => Self::Generic {
                base,
                arguments: arguments.0,
            },
        })
    }
}

/// A language-neutral, parser-derived type shape suitable for persisted
/// signature metadata.
///
/// The shape is stored as a flat post-order arena rather than recursively
/// boxed nodes. Source can contain very deeply nested types, and ordinary
/// operations such as cloning, comparing, hashing, serializing, deserializing
/// and dropping those values must not consume the Rust call stack.
#[derive(Debug, Clone, Serialize)]
pub struct StructuredTypeIdentity {
    nodes: Vec<StructuredTypeNode>,
    root: StructuredTypeNodeId,
    #[serde(skip)]
    edge_count: usize,
    #[serde(skip)]
    string_bytes: usize,
}

#[derive(Serialize, Deserialize)]
struct StructuredTypeIdentityWire {
    nodes: BoundedStructuredTypeNodes,
    root: StructuredTypeNodeId,
}

#[derive(PartialEq, Eq, Hash)]
enum CanonicalStructuredTypeNode {
    Named(StructuredTypeName),
    Pointer(u32),
    Reference(u32),
    Array(u32),
    Slice(u32),
    Map { key: u32, value: u32 },
    Generic { base: u32, arguments: Vec<u32> },
}

#[derive(Clone, Copy)]
enum StructuredTypeTraversalFrame {
    Enter(StructuredTypeNodeId),
    Finish(StructuredTypeNodeId),
}

#[derive(Serialize)]
struct BoundedStructuredTypeNodes(Vec<StructuredTypeNode>);

impl<'de> Deserialize<'de> for BoundedStructuredTypeNodes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NodesVisitor;

        impl<'de> Visitor<'de> for NodesVisitor {
            type Value = BoundedStructuredTypeNodes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_STRUCTURED_TYPE_IDENTITY_NODES} structured type nodes"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > MAX_STRUCTURED_TYPE_IDENTITY_NODES)
                {
                    return Err(serde::de::Error::custom(
                        "structured type identity exceeds the node cap",
                    ));
                }
                let mut nodes = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or_default()
                        .min(MAX_STRUCTURED_TYPE_IDENTITY_NODES),
                );
                let mut edge_count = 0usize;
                let mut string_bytes = 0usize;
                while let Some(node) = sequence.next_element()? {
                    if nodes.len() == MAX_STRUCTURED_TYPE_IDENTITY_NODES {
                        return Err(serde::de::Error::custom(
                            "structured type identity exceeds the node cap",
                        ));
                    }
                    let Some((node_edges, node_string_bytes)) =
                        structured_type_node_resource_cost(&node)
                    else {
                        return Err(serde::de::Error::custom(
                            "structured type identity resource count overflow",
                        ));
                    };
                    edge_count = edge_count.checked_add(node_edges).ok_or_else(|| {
                        serde::de::Error::custom("structured type identity resource count overflow")
                    })?;
                    string_bytes =
                        string_bytes.checked_add(node_string_bytes).ok_or_else(|| {
                            serde::de::Error::custom(
                                "structured type identity resource count overflow",
                            )
                        })?;
                    if edge_count > MAX_STRUCTURED_TYPE_IDENTITY_EDGES {
                        return Err(serde::de::Error::custom(
                            "structured type identity exceeds the edge cap",
                        ));
                    }
                    if string_bytes > MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES {
                        return Err(serde::de::Error::custom(
                            "structured type identity exceeds the string-byte cap",
                        ));
                    }
                    nodes.push(node);
                }
                Ok(BoundedStructuredTypeNodes(nodes))
            }
        }

        deserializer.deserialize_seq(NodesVisitor)
    }
}

impl<'de> Deserialize<'de> for StructuredTypeIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StructuredTypeIdentityWire::deserialize(deserializer)?;
        let identity = Self {
            nodes: wire.nodes.0,
            root: wire.root,
            edge_count: 0,
            string_bytes: 0,
        };
        if !identity.is_valid() {
            return Err(serde::de::Error::custom(
                "invalid flat structured type identity",
            ));
        }
        let Some((edge_count, string_bytes)) = identity.validated_resource_counts() else {
            return Err(serde::de::Error::custom(
                "invalid flat structured type identity",
            ));
        };
        Ok(Self {
            edge_count,
            string_bytes,
            ..identity
        })
    }
}

impl PartialEq for StructuredTypeIdentity {
    fn eq(&self, other: &Self) -> bool {
        let mut interner = HashMap::default();
        let mut visit = || true;
        let Some(left) = self.canonical_root_id_with(&mut interner, &mut visit) else {
            return false;
        };
        let Some(right) = other.canonical_root_id_with(&mut interner, &mut visit) else {
            return false;
        };
        left == right
    }
}

impl Eq for StructuredTypeIdentity {}

impl Hash for StructuredTypeIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash each unique reachable arena node once. Child hashes describe the
        // expanded structural shape, so shared and duplicated representations
        // retain identical hashes without expanding every path through a DAG.
        self.structural_digest().unwrap_or(u64::MAX).hash(state);
    }
}

impl StructuredTypeIdentity {
    fn node(&self, id: StructuredTypeNodeId) -> Option<&StructuredTypeNode> {
        self.nodes.get(id.0 as usize)
    }

    fn reachable_postorder_with(
        &self,
        visit: &mut impl FnMut() -> bool,
    ) -> Option<Vec<StructuredTypeNodeId>> {
        let mut scheduled = HashSet::default();
        let mut pending = vec![StructuredTypeTraversalFrame::Enter(self.root)];
        let mut postorder = Vec::new();
        while let Some(frame) = pending.pop() {
            match frame {
                StructuredTypeTraversalFrame::Enter(id) => {
                    if !scheduled.insert(id) {
                        continue;
                    }
                    if !visit() {
                        return None;
                    }
                    let node = self.node(id)?;
                    pending.push(StructuredTypeTraversalFrame::Finish(id));
                    match node {
                        StructuredTypeNode::Named(_) => {}
                        StructuredTypeNode::Pointer(inner)
                        | StructuredTypeNode::Reference(inner)
                        | StructuredTypeNode::Array(inner)
                        | StructuredTypeNode::Slice(inner) => {
                            pending.push(StructuredTypeTraversalFrame::Enter(*inner));
                        }
                        StructuredTypeNode::Map { key, value } => {
                            pending.push(StructuredTypeTraversalFrame::Enter(*value));
                            pending.push(StructuredTypeTraversalFrame::Enter(*key));
                        }
                        StructuredTypeNode::Generic { base, arguments } => {
                            pending.extend(
                                arguments
                                    .iter()
                                    .rev()
                                    .copied()
                                    .map(StructuredTypeTraversalFrame::Enter),
                            );
                            pending.push(StructuredTypeTraversalFrame::Enter(*base));
                        }
                    }
                }
                StructuredTypeTraversalFrame::Finish(id) => postorder.push(id),
            }
        }
        Some(postorder)
    }

    fn canonical_root_id_with(
        &self,
        interner: &mut HashMap<CanonicalStructuredTypeNode, u32>,
        visit: &mut impl FnMut() -> bool,
    ) -> Option<u32> {
        let mut canonical_ids: HashMap<StructuredTypeNodeId, u32> = HashMap::default();
        for id in self.reachable_postorder_with(visit)? {
            let node = match self.node(id)? {
                StructuredTypeNode::Named(name) => CanonicalStructuredTypeNode::Named(name.clone()),
                StructuredTypeNode::Pointer(inner) => {
                    CanonicalStructuredTypeNode::Pointer(*canonical_ids.get(inner)?)
                }
                StructuredTypeNode::Reference(inner) => {
                    CanonicalStructuredTypeNode::Reference(*canonical_ids.get(inner)?)
                }
                StructuredTypeNode::Array(inner) => {
                    CanonicalStructuredTypeNode::Array(*canonical_ids.get(inner)?)
                }
                StructuredTypeNode::Slice(inner) => {
                    CanonicalStructuredTypeNode::Slice(*canonical_ids.get(inner)?)
                }
                StructuredTypeNode::Map { key, value } => CanonicalStructuredTypeNode::Map {
                    key: *canonical_ids.get(key)?,
                    value: *canonical_ids.get(value)?,
                },
                StructuredTypeNode::Generic { base, arguments } => {
                    CanonicalStructuredTypeNode::Generic {
                        base: *canonical_ids.get(base)?,
                        arguments: arguments
                            .iter()
                            .map(|argument| canonical_ids.get(argument).copied())
                            .collect::<Option<Vec<_>>>()?,
                    }
                }
            };
            let next_id = u32::try_from(interner.len()).ok()?;
            let canonical_id = *interner.entry(node).or_insert(next_id);
            canonical_ids.insert(id, canonical_id);
        }
        canonical_ids.get(&self.root).copied()
    }

    fn structural_digest(&self) -> Option<u64> {
        let mut digests: HashMap<StructuredTypeNodeId, u64> = HashMap::default();
        let mut visit = || true;
        for id in self.reachable_postorder_with(&mut visit)? {
            let mut hasher = DefaultHasher::new();
            match self.node(id)? {
                StructuredTypeNode::Named(name) => {
                    0_u8.hash(&mut hasher);
                    name.hash(&mut hasher);
                }
                StructuredTypeNode::Pointer(inner) => {
                    1_u8.hash(&mut hasher);
                    digests.get(inner)?.hash(&mut hasher);
                }
                StructuredTypeNode::Reference(inner) => {
                    2_u8.hash(&mut hasher);
                    digests.get(inner)?.hash(&mut hasher);
                }
                StructuredTypeNode::Array(inner) => {
                    3_u8.hash(&mut hasher);
                    digests.get(inner)?.hash(&mut hasher);
                }
                StructuredTypeNode::Slice(inner) => {
                    4_u8.hash(&mut hasher);
                    digests.get(inner)?.hash(&mut hasher);
                }
                StructuredTypeNode::Map { key, value } => {
                    5_u8.hash(&mut hasher);
                    digests.get(key)?.hash(&mut hasher);
                    digests.get(value)?.hash(&mut hasher);
                }
                StructuredTypeNode::Generic { base, arguments } => {
                    6_u8.hash(&mut hasher);
                    digests.get(base)?.hash(&mut hasher);
                    arguments.len().hash(&mut hasher);
                    for argument in arguments {
                        digests.get(argument)?.hash(&mut hasher);
                    }
                }
            }
            digests.insert(id, hasher.finish());
        }
        digests.get(&self.root).copied()
    }

    fn is_valid(&self) -> bool {
        if self.node(self.root).is_none() || self.validated_resource_counts().is_none() {
            return false;
        }
        self.nodes.iter().enumerate().all(|(index, node)| {
            if let StructuredTypeNode::Named(name) = node
                && !name.is_valid()
            {
                return false;
            }
            let valid_child = |child: StructuredTypeNodeId| (child.0 as usize) < index;
            match node {
                StructuredTypeNode::Named(_) => true,
                StructuredTypeNode::Pointer(inner)
                | StructuredTypeNode::Reference(inner)
                | StructuredTypeNode::Array(inner)
                | StructuredTypeNode::Slice(inner) => valid_child(*inner),
                StructuredTypeNode::Map { key, value } => valid_child(*key) && valid_child(*value),
                StructuredTypeNode::Generic { base, arguments } => {
                    valid_child(*base) && arguments.iter().copied().all(valid_child)
                }
            }
        })
    }

    pub fn nominal_name(&self) -> Option<&StructuredTypeName> {
        self.nominal_name_with(|| true)
    }

    /// Finds the nominal type while charging the caller once for every arena
    /// node inspected. A false `visit` result stops without returning partial
    /// evidence.
    pub fn nominal_name_with(
        &self,
        mut visit: impl FnMut() -> bool,
    ) -> Option<&StructuredTypeName> {
        let mut current = self.root;
        loop {
            if !visit() {
                return None;
            }
            match self.node(current)? {
                StructuredTypeNode::Named(name) => return Some(name),
                StructuredTypeNode::Pointer(inner) | StructuredTypeNode::Reference(inner) => {
                    current = *inner
                }
                StructuredTypeNode::Generic { base, .. } => current = *base,
                StructuredTypeNode::Array(_)
                | StructuredTypeNode::Slice(_)
                | StructuredTypeNode::Map { .. } => return None,
            }
        }
    }

    /// Consumes an array, slice or map identity and selects its element/value
    /// node without cloning the arena.
    pub fn into_container_element_with(mut self, mut visit: impl FnMut() -> bool) -> Option<Self> {
        if !visit() {
            return None;
        }
        self.root = match self.node(self.root)? {
            StructuredTypeNode::Array(element) | StructuredTypeNode::Slice(element) => *element,
            StructuredTypeNode::Map { value, .. } => *value,
            _ => return None,
        };
        Some(self)
    }

    /// Compares only the reachable type shapes, charging once for each node
    /// inspected in both identities.
    pub fn structurally_eq_with(
        &self,
        other: &Self,
        mut visit: impl FnMut() -> bool,
    ) -> Option<bool> {
        let mut interner = HashMap::default();
        let left = self.canonical_root_id_with(&mut interner, &mut visit)?;
        let right = other.canonical_root_id_with(&mut interner, &mut visit)?;
        Some(left == right)
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self.node(self.root), Some(StructuredTypeNode::Pointer(_)))
    }

    pub fn is_reference(&self) -> bool {
        matches!(self.node(self.root), Some(StructuredTypeNode::Reference(_)))
    }

    pub fn is_array(&self) -> bool {
        matches!(self.node(self.root), Some(StructuredTypeNode::Array(_)))
    }

    pub fn is_slice(&self) -> bool {
        matches!(self.node(self.root), Some(StructuredTypeNode::Slice(_)))
    }

    pub fn is_map(&self) -> bool {
        matches!(self.node(self.root), Some(StructuredTypeNode::Map { .. }))
    }

    pub fn generic_argument_count(&self) -> Option<usize> {
        match self.node(self.root)? {
            StructuredTypeNode::Generic { arguments, .. } => Some(arguments.len()),
            _ => None,
        }
    }

    pub fn wrap_pointer(mut self) -> Option<Self> {
        self.root = self.push_node(StructuredTypeNode::Pointer(self.root))?;
        Some(self)
    }

    pub fn wrap_reference(mut self) -> Option<Self> {
        self.root = self.push_node(StructuredTypeNode::Reference(self.root))?;
        Some(self)
    }

    pub fn wrap_array(mut self) -> Option<Self> {
        self.root = self.push_node(StructuredTypeNode::Array(self.root))?;
        Some(self)
    }

    fn push_node(&mut self, node: StructuredTypeNode) -> Option<StructuredTypeNodeId> {
        let (node_edges, node_string_bytes) = structured_type_node_resource_cost(&node)?;
        let edge_count = self.edge_count.checked_add(node_edges)?;
        let string_bytes = self.string_bytes.checked_add(node_string_bytes)?;
        if self.nodes.len() >= MAX_STRUCTURED_TYPE_IDENTITY_NODES
            || edge_count > MAX_STRUCTURED_TYPE_IDENTITY_EDGES
            || string_bytes > MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES
        {
            return None;
        }
        let id = StructuredTypeNodeId(u32::try_from(self.nodes.len()).ok()?);
        self.nodes.push(node);
        self.edge_count = edge_count;
        self.string_bytes = string_bytes;
        Some(id)
    }

    fn validated_resource_counts(&self) -> Option<(usize, usize)> {
        if self.nodes.len() > MAX_STRUCTURED_TYPE_IDENTITY_NODES {
            return None;
        }
        let mut edge_count = 0usize;
        let mut string_bytes = 0usize;
        for node in &self.nodes {
            let (node_edges, node_string_bytes) = structured_type_node_resource_cost(node)?;
            edge_count = edge_count.checked_add(node_edges)?;
            string_bytes = string_bytes.checked_add(node_string_bytes)?;
            if edge_count > MAX_STRUCTURED_TYPE_IDENTITY_EDGES
                || string_bytes > MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES
            {
                return None;
            }
        }
        Some((edge_count, string_bytes))
    }
}

/// Incremental constructor for a flat [`StructuredTypeIdentity`].
#[derive(Debug, Default)]
pub struct StructuredTypeIdentityBuilder {
    nodes: Vec<StructuredTypeNode>,
    edge_count: usize,
    string_bytes: usize,
}

impl StructuredTypeIdentityBuilder {
    pub fn named(&mut self, name: StructuredTypeName) -> Option<StructuredTypeNodeId> {
        self.push(StructuredTypeNode::Named(name))
    }

    pub fn pointer(&mut self, inner: StructuredTypeNodeId) -> Option<StructuredTypeNodeId> {
        self.push_with_children(StructuredTypeNode::Pointer(inner), &[inner])
    }

    pub fn reference(&mut self, inner: StructuredTypeNodeId) -> Option<StructuredTypeNodeId> {
        self.push_with_children(StructuredTypeNode::Reference(inner), &[inner])
    }

    pub fn array(&mut self, inner: StructuredTypeNodeId) -> Option<StructuredTypeNodeId> {
        self.push_with_children(StructuredTypeNode::Array(inner), &[inner])
    }

    pub fn slice(&mut self, inner: StructuredTypeNodeId) -> Option<StructuredTypeNodeId> {
        self.push_with_children(StructuredTypeNode::Slice(inner), &[inner])
    }

    pub fn map(
        &mut self,
        key: StructuredTypeNodeId,
        value: StructuredTypeNodeId,
    ) -> Option<StructuredTypeNodeId> {
        self.push_with_children(StructuredTypeNode::Map { key, value }, &[key, value])
    }

    pub fn generic(
        &mut self,
        base: StructuredTypeNodeId,
        arguments: Vec<StructuredTypeNodeId>,
    ) -> Option<StructuredTypeNodeId> {
        if !self.contains(base) || !arguments.iter().copied().all(|id| self.contains(id)) {
            return None;
        }
        self.push(StructuredTypeNode::Generic { base, arguments })
    }

    pub fn finish(self, root: StructuredTypeNodeId) -> Option<StructuredTypeIdentity> {
        if !self.contains(root) {
            return None;
        }
        Some(StructuredTypeIdentity {
            nodes: self.nodes,
            root,
            edge_count: self.edge_count,
            string_bytes: self.string_bytes,
        })
    }

    fn push_with_children(
        &mut self,
        node: StructuredTypeNode,
        children: &[StructuredTypeNodeId],
    ) -> Option<StructuredTypeNodeId> {
        if !children.iter().copied().all(|id| self.contains(id)) {
            return None;
        }
        self.push(node)
    }

    fn push(&mut self, node: StructuredTypeNode) -> Option<StructuredTypeNodeId> {
        let (node_edges, node_string_bytes) = structured_type_node_resource_cost(&node)?;
        let edge_count = self.edge_count.checked_add(node_edges)?;
        let string_bytes = self.string_bytes.checked_add(node_string_bytes)?;
        if self.nodes.len() >= MAX_STRUCTURED_TYPE_IDENTITY_NODES
            || edge_count > MAX_STRUCTURED_TYPE_IDENTITY_EDGES
            || string_bytes > MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES
        {
            return None;
        }
        let id = StructuredTypeNodeId(u32::try_from(self.nodes.len()).ok()?);
        self.nodes.push(node);
        self.edge_count = edge_count;
        self.string_bytes = string_bytes;
        Some(id)
    }

    fn contains(&self, id: StructuredTypeNodeId) -> bool {
        (id.0 as usize) < self.nodes.len()
    }
}

fn structured_type_node_resource_cost(node: &StructuredTypeNode) -> Option<(usize, usize)> {
    let edge_count = match node {
        StructuredTypeNode::Named(_) => 0,
        StructuredTypeNode::Pointer(_)
        | StructuredTypeNode::Reference(_)
        | StructuredTypeNode::Array(_)
        | StructuredTypeNode::Slice(_) => 1,
        StructuredTypeNode::Map { .. } => 2,
        StructuredTypeNode::Generic { arguments, .. } => arguments.len().checked_add(1)?,
    };
    let string_bytes = match node {
        StructuredTypeNode::Named(name) => name
            .path
            .iter()
            .chain(&name.lexical_scope)
            .try_fold(0usize, |total, component| {
                total.checked_add(component.len())
            })?,
        StructuredTypeNode::Pointer(_)
        | StructuredTypeNode::Reference(_)
        | StructuredTypeNode::Array(_)
        | StructuredTypeNode::Slice(_)
        | StructuredTypeNode::Map { .. }
        | StructuredTypeNode::Generic { .. } => 0,
    };
    Some((edge_count, string_bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CppTemplateParameterKind {
    Type,
    Value,
    Template,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CppTemplateExpression {
    pub text: String,
    pub term: CppTemplateTerm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CppTemplateTerm {
    Parameter(String),
    Atom {
        kind: String,
        text: String,
    },
    Node {
        kind: String,
        children: Vec<CppTemplateTerm>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CppTemplateParameterMetadata {
    pub name: String,
    pub kind: CppTemplateParameterKind,
    #[serde(default)]
    pub variadic: bool,
    pub default: Option<CppTemplateExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CppTemplateAliasTargetMetadata {
    pub components: Vec<String>,
    pub global: bool,
    pub arguments: Option<Vec<CppTemplateExpression>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CppTemplateMetadata {
    pub primary_name: String,
    pub primary_fq_name: String,
    pub parameters: Vec<CppTemplateParameterMetadata>,
    pub specialization_arguments: Vec<CppTemplateExpression>,
    #[serde(default)]
    pub alias_target: Option<CppTemplateAliasTargetMetadata>,
}

impl SignatureMetadata {
    pub fn new(label: impl Into<String>, parameters: Vec<ParameterMetadata>) -> Self {
        Self {
            label: label.into(),
            parameters,
            return_type_text: None,
            return_type_identity: None,
            declaration_only: false,
            callable_arity: None,
            type_parameters: Vec::new(),
            bare_return_type_parameter: None,
            callable_linkage: None,
            dispatch_extensibility: None,
            extension_receiver_type: None,
            extension_receiver_type_identity: None,
            extension_receiver_is_unconstrained_type_parameter: false,
            field_is_static: false,
            field_is_final: false,
            companion_object: false,
        }
    }

    pub fn with_parameter_labels(label: impl Into<String>, labels: Vec<String>) -> Self {
        let label = label.into();
        let (params_start, params_end) = match label.find('(') {
            Some(open_paren) => (
                open_paren + 1,
                matching_close_paren(&label, open_paren).unwrap_or(label.len()),
            ),
            None => (0, label.len()),
        };
        let mut search_start = params_start;
        let parameters = labels
            .into_iter()
            .filter_map(|parameter_label| {
                if parameter_label.is_empty() || search_start > params_end {
                    return None;
                }
                let haystack = label.get(search_start..params_end)?;
                let relative_start = haystack.find(&parameter_label)?;
                let start_byte = search_start + relative_start;
                let end_byte = start_byte + parameter_label.len();
                search_start = end_byte;
                Some(ParameterMetadata::new(
                    parameter_label,
                    start_byte,
                    end_byte,
                ))
            })
            .collect();
        Self {
            label,
            parameters,
            return_type_text: None,
            return_type_identity: None,
            declaration_only: false,
            callable_arity: None,
            type_parameters: Vec::new(),
            bare_return_type_parameter: None,
            callable_linkage: None,
            dispatch_extensibility: None,
            extension_receiver_type: None,
            extension_receiver_type_identity: None,
            extension_receiver_is_unconstrained_type_parameter: false,
            field_is_static: false,
            field_is_final: false,
            companion_object: false,
        }
    }

    pub fn with_return_type_text(mut self, return_type_text: Option<impl Into<String>>) -> Self {
        self.return_type_text = return_type_text
            .map(Into::into)
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty());
        self
    }

    pub fn with_field_modifiers(mut self, is_static: bool, is_final: bool) -> Self {
        self.field_is_static = is_static;
        self.field_is_final = is_final;
        self
    }

    pub fn with_return_type_identity(
        mut self,
        return_type_identity: Option<StructuredTypeIdentity>,
    ) -> Self {
        self.return_type_identity = return_type_identity;
        self
    }

    pub fn with_declaration_only(mut self, declaration_only: bool) -> Self {
        self.declaration_only = declaration_only;
        self
    }

    pub fn with_callable_arity(mut self, callable_arity: CallableArity) -> Self {
        self.callable_arity = Some(callable_arity);
        self
    }

    pub fn with_type_parameters(mut self, type_parameters: Vec<String>) -> Self {
        self.type_parameters = type_parameters;
        self
    }

    pub fn with_bare_return_type_parameter(
        mut self,
        bare_return_type_parameter: Option<impl Into<String>>,
    ) -> Self {
        self.bare_return_type_parameter = bare_return_type_parameter
            .map(Into::into)
            .map(|parameter| parameter.trim().to_string())
            .filter(|parameter| !parameter.is_empty());
        self
    }

    pub fn with_callable_linkage(mut self, linkage: CallableLinkage) -> Self {
        self.callable_linkage = Some(linkage);
        self
    }

    pub fn with_dispatch_extensibility(
        mut self,
        dispatch_extensibility: DispatchExtensibility,
    ) -> Self {
        self.dispatch_extensibility = Some(dispatch_extensibility);
        self
    }

    pub fn with_extension_receiver_type(
        mut self,
        extension_receiver_type: Option<impl Into<String>>,
    ) -> Self {
        self.extension_receiver_type = extension_receiver_type
            .map(Into::into)
            .map(|receiver_type| receiver_type.trim().to_string())
            .filter(|receiver_type| !receiver_type.is_empty());
        self
    }

    pub fn with_extension_receiver_type_identity(
        mut self,
        extension_receiver_type_identity: Option<StructuredTypeIdentity>,
    ) -> Self {
        self.extension_receiver_type_identity = extension_receiver_type_identity;
        self
    }

    pub fn with_extension_receiver_is_unconstrained_type_parameter(
        mut self,
        extension_receiver_is_unconstrained_type_parameter: bool,
    ) -> Self {
        self.extension_receiver_is_unconstrained_type_parameter =
            extension_receiver_is_unconstrained_type_parameter;
        self
    }

    /// Mark this as the signature of a Kotlin `companion object`.
    pub fn with_companion_object(mut self, companion_object: bool) -> Self {
        self.companion_object = companion_object;
        self
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn parameters(&self) -> &[ParameterMetadata] {
        &self.parameters
    }

    pub fn return_type_text(&self) -> Option<&str> {
        self.return_type_text.as_deref()
    }

    pub fn field_is_static(&self) -> bool {
        self.field_is_static
    }

    pub fn field_is_final(&self) -> bool {
        self.field_is_final
    }

    pub fn return_type_identity(&self) -> Option<&StructuredTypeIdentity> {
        self.return_type_identity.as_ref()
    }

    pub fn into_return_type_identity(self) -> Option<StructuredTypeIdentity> {
        self.return_type_identity
    }

    pub fn is_declaration_only(&self) -> bool {
        self.declaration_only
    }

    pub fn callable_arity(&self) -> Option<CallableArity> {
        self.callable_arity
    }

    pub fn type_parameters(&self) -> &[String] {
        &self.type_parameters
    }

    pub fn bare_return_type_parameter(&self) -> Option<&str> {
        self.bare_return_type_parameter.as_deref()
    }

    pub fn callable_linkage(&self) -> Option<CallableLinkage> {
        self.callable_linkage
    }

    pub const fn dispatch_extensibility(&self) -> Option<DispatchExtensibility> {
        self.dispatch_extensibility
    }

    pub fn extension_receiver_type(&self) -> Option<&str> {
        self.extension_receiver_type.as_deref()
    }

    pub fn extension_receiver_type_identity(&self) -> Option<&StructuredTypeIdentity> {
        self.extension_receiver_type_identity.as_ref()
    }

    pub const fn extension_receiver_is_unconstrained_type_parameter(&self) -> bool {
        self.extension_receiver_is_unconstrained_type_parameter
    }

    /// Whether this is the signature of a Kotlin `companion object`.
    pub const fn is_companion_object(&self) -> bool {
        self.companion_object
    }
}

fn matching_close_paren(label: &str, open_paren: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in label.get(open_paren..)?.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_paren + index);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct ProjectFileInner {
    root: PathBuf,
    rel_path: PathBuf,
}

#[derive(Clone)]
pub struct ProjectFile(Arc<ProjectFileInner>);

impl ProjectFile {
    pub fn new(root: impl Into<PathBuf>, rel_path: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let rel_path = rel_path.into();

        assert!(root.is_absolute(), "project root must be absolute");
        assert!(
            !rel_path.is_absolute(),
            "project file path must be relative"
        );

        Self(Arc::new(ProjectFileInner {
            root: root.normalize(),
            rel_path: rel_path.normalize(),
        }))
    }

    pub fn root(&self) -> &Path {
        &self.0.root
    }

    pub fn rel_path(&self) -> &Path {
        &self.0.rel_path
    }

    pub fn abs_path(&self) -> PathBuf {
        self.0.root.join(&self.0.rel_path)
    }

    pub fn parent(&self) -> PathBuf {
        self.0
            .rel_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    pub fn exists(&self) -> bool {
        self.abs_path().exists()
    }

    pub fn is_binary(&self) -> io::Result<bool> {
        let path = self.abs_path();
        if !path.exists() || !path.is_file() {
            return Ok(false);
        }

        let mut file = File::open(path)?;
        let mut buf = [0u8; 8192];
        let read = file.read(&mut buf)?;
        Ok(buf[..read].contains(&0))
    }

    pub fn read_to_string(&self) -> io::Result<String> {
        std::fs::read_to_string(self.abs_path())
    }

    pub fn write(&self, contents: impl AsRef<str>) -> io::Result<()> {
        if let Some(parent) = self.abs_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.abs_path(), contents.as_ref())
    }
}

impl fmt::Debug for ProjectFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectFile")
            .field("root", &self.0.root)
            .field("rel_path", &self.0.rel_path)
            .finish()
    }
}

impl PartialEq for ProjectFile {
    fn eq(&self, other: &Self) -> bool {
        self.0.root == other.0.root && self.0.rel_path == other.0.rel_path
    }
}

impl Eq for ProjectFile {}

impl Hash for ProjectFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.root.hash(state);
        self.0.rel_path.hash(state);
    }
}

impl Ord for ProjectFile {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.root.cmp(&other.0.root) {
            Ordering::Equal => self.0.rel_path.cmp(&other.0.rel_path),
            ordering => ordering,
        }
    }
}

impl PartialOrd for ProjectFile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ProjectFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.rel_path.display())
    }
}

/// Where a persisted unit's package prefix is anchored when it is re-resolved
/// at hydration time. `None` on the unit means "use the language adapter's
/// default anchor". This is process-local provenance recorded by the extractor;
/// it is never itself persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PackageAnchor {
    /// Anchored at the file's own module package, popped up `pop` levels
    /// (`pop` is relative to the file-package boundary, floor 0).
    OwnModule { pop: u8 },
    /// Anchored at the crate root of the file's crate.
    CrateRoot,
}

#[derive(Debug, Clone)]
struct CodeUnitInner {
    source: ProjectFile,
    kind: CodeUnitType,
    signature: Option<String>,
    synthetic: bool,
    fq: FqName,
    package_segment_count: usize,
    package_anchor: Option<PackageAnchor>,
    rendered_name: RenderedCodeUnitName,
}

#[derive(Debug, Clone)]
struct RenderedCodeUnitName {
    display: String,
    package_end: usize,
    short_start: usize,
    identifier_start: usize,
    owner_identifier: Option<(usize, usize)>,
}

impl RenderedCodeUnitName {
    fn new(source: &ProjectFile, fq: &FqName, package_segment_count: usize) -> Self {
        let language = crate::analyzer::common::language_for_file(source);
        let interner = segment_interner();
        let package = fq
            .prefix(package_segment_count)
            .display_native(language, interner);
        let short = fq
            .suffix_from(package_segment_count)
            .display_native(language, interner);
        let identifier = fq
            .suffix_from(fq.len() - 1)
            .display_native(language, interner);
        let display = fq.display_native(language, interner);
        let owner_identifier = (fq.len() >= 2).then(|| {
            let owner_prefix = fq.prefix(fq.len() - 1);
            let owner_display = owner_prefix.display_native(language, interner);
            let owner_terminal = owner_prefix
                .suffix_from(owner_prefix.len() - 1)
                .display_native(language, interner);
            assert!(
                display.starts_with(&owner_display) && owner_display.ends_with(&owner_terminal),
                "structured CodeUnit owner identifier must be a slice of its rendered FqName"
            );
            (
                owner_display.len() - owner_terminal.len(),
                owner_display.len(),
            )
        });
        assert!(
            display.starts_with(&package) && display.ends_with(&short),
            "structured CodeUnit projections must be slices of its rendered FqName"
        );
        assert!(
            display.ends_with(&identifier),
            "structured CodeUnit identifier must be the rendered terminal segment"
        );
        Self {
            package_end: package.len(),
            short_start: display.len() - short.len(),
            identifier_start: display.len() - identifier.len(),
            owner_identifier,
            display,
        }
    }
}

#[derive(Clone)]
pub struct CodeUnit(Arc<CodeUnitInner>);

impl CodeUnit {
    pub fn new(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
    ) -> Self {
        Self::with_signature(source, kind, package_name, short_name, None, false)
    }

    pub fn with_signature(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
        signature: Option<String>,
        synthetic: bool,
    ) -> Self {
        let package_name = package_name.into();
        let short_name = short_name.into();
        let mut fq = FqName::new();
        let package_segment_count = if package_name.is_empty() {
            0
        } else {
            fq.push(segment_interner().intern(&package_name, SegmentKind::Package));
            1
        };
        let tail_kind = match kind {
            CodeUnitType::Class => SegmentKind::Type,
            CodeUnitType::Module => SegmentKind::Package,
            CodeUnitType::FileScope => SegmentKind::Path,
            _ => SegmentKind::Member,
        };
        fq.push(segment_interner().intern(&short_name, tail_kind));
        Self::from_fq(
            source,
            kind,
            fq,
            package_segment_count,
            signature,
            synthetic,
        )
    }

    /// Extractor entry point for an authoritative structured name. The textual
    /// projections locate and validate its package boundary, then are
    /// discarded; they are never stored as identity.
    pub fn with_signature_and_fq(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
        signature: Option<String>,
        synthetic: bool,
        fq: FqName,
    ) -> Self {
        let package_name = package_name.into();
        let short_name = short_name.into();
        assert!(
            !fq.is_empty() && !short_name.is_empty(),
            "short_name must not be empty (kind={kind:?}, package_name={package_name:?}, source={source}, signature={signature:?}, synthetic={synthetic})"
        );
        let language = crate::analyzer::common::language_for_file(&source);
        let interner = segment_interner();
        let package_segment_count = (0..=fq.len())
            .find(|&prefix_len| {
                fq.prefix(prefix_len).display_native(language, interner) == package_name
                    && fq
                        .suffix_from(prefix_len)
                        .display_native(language, interner)
                        == short_name
            })
            .unwrap_or_else(|| {
                panic!(
                    "FqName does not contain the supplied package/short boundary \
                     (kind={kind:?}, language={language:?}, package_name={package_name:?}, \
                     short_name={short_name:?}, fq={:?})",
                    fq.display_native(language, interner),
                )
            });
        Self::from_fq(
            source,
            kind,
            fq,
            package_segment_count,
            signature,
            synthetic,
        )
    }

    pub fn from_fq(
        source: ProjectFile,
        kind: CodeUnitType,
        fq: FqName,
        package_segment_count: usize,
        signature: Option<String>,
        synthetic: bool,
    ) -> Self {
        assert!(!fq.is_empty(), "CodeUnit FqName must not be empty");
        assert!(
            package_segment_count < fq.len(),
            "CodeUnit package prefix must leave a non-empty declaration tail"
        );
        let rendered_name = RenderedCodeUnitName::new(&source, &fq, package_segment_count);
        Self(Arc::new(CodeUnitInner {
            source,
            kind,
            signature,
            synthetic,
            fq,
            package_segment_count,
            package_anchor: None,
            rendered_name,
        }))
    }

    /// Construct a unit from an extractor-provided structured name.
    pub fn new_fq(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
        fq: FqName,
    ) -> Self {
        Self::with_signature_and_fq(source, kind, package_name, short_name, None, false, fq)
    }

    pub fn file_scope(source: ProjectFile) -> Self {
        let short_name = source.rel_path().to_string_lossy().replace('\\', "/");
        Self::with_signature(
            source,
            CodeUnitType::FileScope,
            String::new(),
            short_name,
            None,
            true,
        )
    }

    pub fn source(&self) -> &ProjectFile {
        &self.0.source
    }

    pub fn kind(&self) -> CodeUnitType {
        self.0.kind
    }

    pub fn package_name(&self) -> &str {
        &self.0.rendered_name.display[..self.0.rendered_name.package_end]
    }

    pub fn short_name(&self) -> &str {
        &self.0.rendered_name.display[self.0.rendered_name.short_start..]
    }

    pub fn fq(&self) -> &FqName {
        &self.0.fq
    }

    pub fn package_segment_count(&self) -> usize {
        self.0.package_segment_count
    }

    pub fn package_fq(&self) -> FqName {
        self.0.fq.prefix(self.0.package_segment_count)
    }

    /// Debug/test-only view of the structured `fq` as ordered `(kind_name,
    /// text)` pairs. Public so integration tests in `tests/` (compiled against
    /// the lib in debug builds, where `debug_assertions` is on) can assert that
    /// a cache round-trip preserved every segment's KIND and TEXT — not merely
    /// the joined string — without leaking the crate-private `SegmentKind` or
    /// interner types. See `tests/analyzer_persistence.rs`.
    #[cfg(any(test, debug_assertions))]
    pub fn fq_segments_debug(&self) -> Vec<(&'static str, String)> {
        let interner = crate::analyzer::fq_name::segment_interner();
        self.0
            .fq
            .segments()
            .iter()
            .map(|&id| {
                let (text, kind) = interner.resolve(id);
                (kind.name(), text.to_string())
            })
            .collect()
    }

    pub fn signature(&self) -> Option<&str> {
        self.0.signature.as_deref()
    }

    pub fn is_synthetic(&self) -> bool {
        self.0.synthetic
    }

    pub fn is_anonymous(&self) -> bool {
        self.short_name().contains("$anon$")
    }

    pub fn fq_name(&self) -> String {
        self.0.rendered_name.display.clone()
    }

    // This is the structural identifier used by lookup, import, and usage code.
    // For user-facing names, prefer the display helpers in `analyzer::common`
    // so languages like Scala can render idiomatic names without changing the
    // matching semantics encoded here.
    pub fn identifier(&self) -> &str {
        &self.0.rendered_name.display[self.0.rendered_name.identifier_start..]
    }

    /// The terminal segment of this declaration's structural owner, if any.
    /// This is derived directly from the penultimate [`FqName`] segment; it
    /// never guesses an owner boundary by splitting the rendered name.
    pub fn owner_identifier(&self) -> Option<&str> {
        self.0
            .rendered_name
            .owner_identifier
            .map(|(start, end)| &self.0.rendered_name.display[start..end])
    }

    /// Record where this unit's package prefix is anchored, so persistence can
    /// store a content-stable tail instead of a path-derived absolute prefix.
    pub fn with_package_anchor(mut self, anchor: PackageAnchor) -> Self {
        Arc::make_mut(&mut self.0).package_anchor = Some(anchor);
        self
    }

    /// The extractor-recorded anchor, or `None` to mean "use the language
    /// adapter's default anchor".
    pub fn package_anchor(&self) -> Option<PackageAnchor> {
        self.0.package_anchor
    }

    // Rebuilders clone the inner and mutate one field: reconstructing via
    // `from_fq` would silently drop `package_anchor` and re-persist a
    // path-derived absolute prefix.
    pub fn without_signature(&self) -> Self {
        let mut inner = (*self.0).clone();
        inner.signature = None;
        Self(Arc::new(inner))
    }

    pub fn with_synthetic(&self, synthetic: bool) -> Self {
        let mut inner = (*self.0).clone();
        inner.synthetic = synthetic;
        Self(Arc::new(inner))
    }

    pub fn is_class(&self) -> bool {
        self.0.kind == CodeUnitType::Class
    }

    pub fn is_function(&self) -> bool {
        self.is_callable()
    }

    pub fn is_callable(&self) -> bool {
        self.0.kind.is_callable_kind()
    }

    pub fn is_field(&self) -> bool {
        self.0.kind == CodeUnitType::Field
    }

    pub fn is_module(&self) -> bool {
        self.0.kind == CodeUnitType::Module
    }

    pub fn is_macro(&self) -> bool {
        self.0.kind == CodeUnitType::Macro
    }

    pub fn is_file_scope(&self) -> bool {
        self.0.kind == CodeUnitType::FileScope
    }
}

impl fmt::Debug for CodeUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeUnit")
            .field("source", &self.0.source)
            .field("kind", &self.0.kind)
            .field("fq", &self.0.fq)
            .field("package_segment_count", &self.0.package_segment_count)
            .field("package_name", &self.package_name())
            .field("short_name", &self.short_name())
            .field("signature", &self.0.signature)
            .field("synthetic", &self.0.synthetic)
            .finish()
    }
}

impl PartialEq for CodeUnit {
    fn eq(&self, other: &Self) -> bool {
        self.0.source == other.0.source
            && self.0.kind == other.0.kind
            && self.0.fq == other.0.fq
            && self.0.package_segment_count == other.0.package_segment_count
            && self.0.signature == other.0.signature
            && self.0.synthetic == other.0.synthetic
    }
}

impl Eq for CodeUnit {}

impl Hash for CodeUnit {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.source.hash(state);
        self.0.kind.hash(state);
        self.0.fq.hash(state);
        self.0.package_segment_count.hash(state);
        self.0.signature.hash(state);
        self.0.synthetic.hash(state);
    }
}

impl Ord for CodeUnit {
    fn cmp(&self, other: &Self) -> Ordering {
        self.package_name()
            .cmp(other.package_name())
            .then_with(|| self.short_name().cmp(other.short_name()))
            .then_with(|| self.0.kind.cmp(&other.0.kind))
            .then_with(|| self.0.source.cmp(&other.0.source))
            .then_with(|| self.0.signature.cmp(&other.0.signature))
            .then_with(|| self.0.synthetic.cmp(&other.0.synthetic))
    }
}

impl PartialOrd for CodeUnit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Range {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

/// The persisted facts required to render one file's declaration summary.
///
/// This deliberately differs from `FileState`: it is a read model for summary
/// rendering and omits unrelated imports, types, graph edges, and diagnostics.
#[derive(Debug, Clone, Default)]
pub struct SummaryFileProjection {
    pub top_level_declarations: Vec<CodeUnit>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub ranges: HashMap<CodeUnit, Vec<Range>>,
    pub children: HashMap<CodeUnit, Vec<CodeUnit>>,
}

/// Persisted facts needed to rank and render one symbol-search result without
/// hydrating the complete source file state.
#[derive(Debug, Clone)]
pub struct SearchSymbolCandidate {
    pub code_unit: CodeUnit,
    pub primary_range: Option<Range>,
    /// Per-declaration test-region taint (issue #1102): whether this specific
    /// symbol is inside a structurally-evidenced test region. `search_symbols`
    /// combines it with a path-based test check to decide test filtering, so a
    /// production symbol in a file with inline tests still surfaces.
    pub in_test_region: bool,
}

/// A tree-sitter parse-error span captured during analysis so the LSP
/// diagnostic handler can skip re-parsing on every request. `kind` records
/// whether tree-sitter flagged the span as an `ERROR` node or a `MISSING`
/// child; for missing nodes we also keep the grammar's expected-node name so
/// the diagnostic message reads "missing foo".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub range: Range,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A tree-sitter `ERROR` node — unexpected/unparseable input.
    Error,
    /// A `MISSING` node — the parser inserted a placeholder for a token the
    /// grammar required. The wrapped string is the node kind that was
    /// expected (e.g. `"}"`, `";"`).
    Missing(String),
}

/// Comment line counts and span lines for a [`CodeUnit`], with optional roll-up
/// of nested declarations (e.g. methods inside a class). Mirrors brokk-shared
/// `CommentDensityStats` field-for-field so report output stays byte-for-byte
/// equivalent to brokk-core MCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentDensityStats {
    pub fq_name: String,
    pub relative_path: String,
    pub header_comment_lines: u32,
    pub inline_comment_lines: u32,
    /// Lines covered by this declaration's ranges (may sum overload ranges).
    pub span_lines: u32,
    /// Header lines including nested declarations (for class-like units equals own plus children).
    pub rolled_up_header_comment_lines: u32,
    /// Inline lines including nested declarations.
    pub rolled_up_inline_comment_lines: u32,
    /// Span lines including nested declarations (sum of descendant spans for roll-up).
    pub rolled_up_span_lines: u32,
}

/// Tunable weights for test-assertion smell detection. Mirrors the Brokk
/// analyzer defaults so MCP output stays behaviorally aligned when Bifrost is
/// used as a drop-in replacement for this tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestAssertionWeights {
    pub no_assertion_weight: i32,
    pub tautological_assertion_weight: i32,
    pub constant_truth_weight: i32,
    pub constant_equality_weight: i32,
    pub nullness_only_weight: i32,
    pub shallow_assertion_only_weight: i32,
    pub overspecified_literal_weight: i32,
    pub anonymous_test_double_weight: i32,
    pub repeated_anonymous_test_double_weight: i32,
    pub meaningful_assertion_credit: i32,
    pub meaningful_assertion_credit_cap: i32,
    pub large_literal_length_threshold: i32,
}

impl TestAssertionWeights {
    pub fn defaults() -> Self {
        Self {
            no_assertion_weight: 5,
            tautological_assertion_weight: 6,
            constant_truth_weight: 4,
            constant_equality_weight: 4,
            nullness_only_weight: 2,
            shallow_assertion_only_weight: 2,
            overspecified_literal_weight: 2,
            anonymous_test_double_weight: 3,
            repeated_anonymous_test_double_weight: 5,
            meaningful_assertion_credit: 1,
            meaningful_assertion_credit_cap: 4,
            large_literal_length_threshold: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAssertionSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub assertion_kind: String,
    pub score: i32,
    pub assertion_count: i32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    pub start_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAssertionAnalysis {
    pub findings: Vec<TestAssertionSmell>,
    /// Candidates consumed from an explicit work budget. `None` means the
    /// analyzer preserves its legacy unbounded implementation.
    pub inspected_candidates: Option<usize>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneSmellWeights {
    pub min_normalized_tokens: i32,
    pub min_similarity_percent: i32,
    pub shingle_size: i32,
    pub min_shared_shingles: i32,
    pub ast_similarity_percent: i32,
}

impl CloneSmellWeights {
    pub fn defaults() -> Self {
        Self {
            min_normalized_tokens: 12,
            min_similarity_percent: 60,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub peer_file: ProjectFile,
    pub peer_enclosing_fq_name: String,
    pub score: i32,
    pub normalized_token_count: i32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    pub peer_excerpt: String,
}

/// Tunable weights for the exception-handling smell heuristic. Mirrors
/// brokk-shared `IAnalyzer.ExceptionSmellWeights` field-for-field; callers
/// can override individual fields by passing positive values and otherwise
/// fall back to [`ExceptionSmellWeights::defaults`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionSmellWeights {
    pub generic_throwable_weight: i32,
    pub generic_exception_weight: i32,
    pub generic_runtime_exception_weight: i32,
    pub empty_body_weight: i32,
    pub comment_only_body_weight: i32,
    pub small_body_weight: i32,
    pub log_only_weight: i32,
    pub meaningful_body_credit_per_statement: i32,
    pub meaningful_body_statement_threshold: i32,
    pub small_body_max_statements: i32,
}

impl ExceptionSmellWeights {
    /// Default weights copied verbatim from brokk-shared
    /// `IAnalyzer.ExceptionSmellWeights.defaults()` — keep these in lock-step
    /// so identical input files produce identical scores across the two MCP
    /// servers.
    pub fn defaults() -> Self {
        Self {
            generic_throwable_weight: 5,
            generic_exception_weight: 3,
            generic_runtime_exception_weight: 2,
            empty_body_weight: 5,
            comment_only_body_weight: 4,
            small_body_weight: 2,
            log_only_weight: 2,
            meaningful_body_credit_per_statement: 1,
            meaningful_body_statement_threshold: 6,
            small_body_max_statements: 2,
        }
    }
}

/// One suspicious catch handler reported by the analyzer. Mirrors
/// brokk-shared `IAnalyzer.ExceptionHandlingSmell`. Not serde-derived —
/// the embedded [`ProjectFile`] is only constructed inside the analyzer
/// and the report layer rebuilds the rendered table from these in-memory
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandlingSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub catch_type: String,
    pub score: i32,
    pub body_statement_count: u32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    /// Source byte offset of the `catch` clause; used as the deterministic
    /// tie-breaker when two findings share score, file, and enclosing symbol.
    /// Not surfaced in the markdown report — kept here so callers ranking or
    /// deduping can stay stable.
    pub start_byte: usize,
}

/// Capability-honest result of analyzing one file for exception-handling
/// smells. An empty [`Self::Analyzed`] result is authoritative; unsupported
/// semantics and analysis failures must never be represented as clean files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionHandlingAnalysis {
    Analyzed(Vec<ExceptionHandlingSmell>),
    Unsupported { reason: String },
    Failed { message: String },
}

impl Range {
    pub fn contains(&self, other: &Range) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }

    /// Mirrors brokk-shared `Range.isEmpty()` so the maintainability-size
    /// heuristic skips degenerate ranges identically to the JVM analyzer.
    pub fn is_empty(&self) -> bool {
        self.start_line == self.end_line && self.start_byte == self.end_byte
    }

    /// Number of source lines this range spans. Matches brokk-shared
    /// `IAnalyzer.spanLines(Range)`: empty ranges report `0`, non-empty
    /// ranges report at least `1`.
    ///
    /// API note: brokk-shared puts this on `IAnalyzer` (static helper);
    /// bifrost places it on `Range` because the computation depends only
    /// on the range's own fields. Do not "re-align" by adding a trait
    /// method — the current placement is intentional.
    pub fn span_lines(&self) -> u32 {
        if self.is_empty() {
            return 0;
        }
        let diff = self.end_line.saturating_sub(self.start_line) + 1;
        diff.max(1) as u32
    }
}

/// Tunable thresholds for the long-method / god-object maintainability-size
/// heuristic. Mirrors brokk-shared `IAnalyzer.MaintainabilitySizeSmellWeights`
/// field-for-field; the brokk-core MCP wrapper falls back to
/// [`MaintainabilitySizeSmellWeights::defaults`] whenever a knob is `<= 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintainabilitySizeSmellWeights {
    pub long_method_span_lines: i32,
    pub high_complexity_threshold: i32,
    pub god_object_span_lines: i32,
    pub god_object_direct_children: i32,
    pub god_object_functions: i32,
    pub helper_sprawl_functions: i32,
    pub helper_sprawl_workflow_lines: i32,
    pub file_module_leeway_multiplier: i32,
}

impl MaintainabilitySizeSmellWeights {
    /// Default thresholds copied verbatim from brokk-shared
    /// `IAnalyzer.MaintainabilitySizeSmellWeights.defaults()`. Keep these in
    /// lock-step so identical input files produce identical scores across
    /// the two MCP servers.
    pub fn defaults() -> Self {
        Self {
            long_method_span_lines: 80,
            high_complexity_threshold: 10,
            god_object_span_lines: 300,
            god_object_direct_children: 20,
            god_object_functions: 15,
            helper_sprawl_functions: 10,
            helper_sprawl_workflow_lines: 60,
            file_module_leeway_multiplier: 2,
        }
    }
}

/// One oversized function/class/module finding reported by the
/// maintainability-size heuristic. Mirrors brokk-shared
/// `IAnalyzer.MaintainabilitySizeSmell`. Not serde-derived — the embedded
/// [`CodeUnit`] only round-trips through analyzer state, and the report
/// layer renders directly from these in-memory values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintainabilitySizeSmell {
    pub code_unit: CodeUnit,
    pub range: Range,
    pub score: i32,
    pub own_span_lines: u32,
    pub descendant_span_lines: u32,
    pub direct_child_count: u32,
    pub function_count: u32,
    pub nested_type_count: u32,
    pub max_function_span_lines: u32,
    pub max_cyclomatic_complexity: u32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredImportPath {
    pub segments: Vec<String>,
    /// Parser-derived import form. This lets consumers distinguish
    /// `import pkg.mod` from `from pkg import mod` without reparsing text.
    #[serde(default)]
    pub kind: Option<StructuredImportPathKind>,
    /// Lexical namespace/package prefixes at the import declaration, ordered
    /// from outermost to innermost and derived by the language parser.
    #[serde(default)]
    pub lexical_prefixes: Vec<String>,
    /// Parser-derived lexical containers surrounding the import, ordered
    /// outermost to innermost.
    #[serde(default)]
    pub lexical_scopes: Vec<StructuredImportScope>,
    /// Start byte of the import declaration, used for source-order visibility.
    #[serde(default)]
    pub declaration_start_byte: usize,
}

impl StructuredImportPath {
    /// Render all path segments joined by `separator`. Shared by adapters
    /// that reimplement plain segment-joining over this model, e.g. go's
    /// `/`-joined package path and scala's `.`-joined qualified names. Only
    /// a drop-in replacement for call sites that join the *whole* segment
    /// list; slicing/prefix joins over a subset of segments stay bespoke.
    pub fn render_segments(&self, separator: &str) -> String {
        self.segments.join(separator)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuredImportPathKind {
    Namespace,
    ImportFrom,
    /// A member import declared with a `static` token (Java's
    /// `import static a.b.C.member;`). The parser records the token so
    /// consumers never re-derive staticness from `raw_snippet` text.
    StaticMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredImportScope {
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportInfo {
    pub raw_snippet: String,
    pub is_wildcard: bool,
    pub identifier: Option<String>,
    pub alias: Option<String>,
    /// Parser-derived path components. Language adapters should populate this
    /// from syntax-tree fields instead of making consumers recover structure
    /// from `raw_snippet`.
    #[serde(default)]
    pub path: Option<StructuredImportPath>,
    /// Byte span of the token that spells the name this import binds in the
    /// importing scope: the alias token when the import is renamed, the
    /// imported name's own token otherwise. This is what tells two rows of one
    /// declaration (`from pkg import alpha, beta`) apart structurally. `None`
    /// when the adapter cannot point at one token: a wildcard binds no single
    /// name, and some desugared forms spell the bound name only inside a
    /// compound token.
    #[serde(default)]
    pub binder_span: Option<crate::analyzer::structural::facts::Span>,
}

impl ImportInfo {
    /// The name this import binds in the importing scope: the explicit
    /// `alias` if the language recorded one, otherwise the parsed
    /// `identifier`, otherwise the tail (last segment) of the structured
    /// import path when the parser recorded one and neither of the above is
    /// present.
    ///
    /// This is the common `alias ?? identifier ?? tail-of-path` desugar shape
    /// shared by several language adapters. It is intentionally narrow: a
    /// site should only switch to it when its own fallback order and
    /// tail-of-path semantics agree with this one exactly (some languages
    /// normalize separators, split on a different delimiter, or fall back to
    /// something other than the last path segment — those stay bespoke).
    pub fn local_name(&self) -> Option<&str> {
        self.alias
            .as_deref()
            .or(self.identifier.as_deref())
            .or_else(|| {
                self.path
                    .as_ref()
                    .and_then(|path| path.segments.last())
                    .map(String::as_str)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiagnostic {
    pub range: Range,
    pub source: &'static str,
    pub kind: &'static str,
    pub message: String,
}

/// The structured surface that a semantic name lookup checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticDomain {
    LexicalScope { file: PathBuf, range: Range },
    Module { name: String },
    Package { name: String },
    Type { name: String },
    MemberSurface { owner: String, member: String },
}

/// Complete evidence that a symbol does not exist in a checked domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticAbsenceProof {
    pub range: Range,
    pub domain: SemanticDiagnosticDomain,
    pub boundary: BoundaryStatus,
}

/// A typed cause that prevents a semantic lookup from proving absence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticIncompleteReason {
    MissingDependencyDiscovery { boundary: BoundaryStatus },
    StaleGeneration { expected: u64, actual: u64 },
    Cancelled,
    Truncated,
    UnsupportedSemantics { detail: String },
    DynamicBehavior { detail: String },
    RuntimeUnavailable { detail: String },
    CorruptSemanticPack { detail: String },
    UnsupportedGeneratedSurface { detail: String },
}

/// The result of one structured lookup made while collecting diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticOutcome {
    Resolved {
        range: Range,
        boundary: BoundaryStatus,
    },
    Ambiguous {
        range: Range,
        boundaries: Vec<BoundaryStatus>,
    },
    Absent(SemanticAbsenceProof),
    Incomplete {
        range: Option<Range>,
        reasons: Vec<SemanticDiagnosticIncompleteReason>,
    },
}

/// Whether every diagnostic candidate in one request had complete evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticReportStatus {
    Complete,
    Incomplete,
}

/// Semantic diagnostics and the structured proof or suppression result behind them.
///
/// The fields stay private so a caller cannot add an error without a complete
/// [`SemanticAbsenceProof`]. Parse diagnostics use a separate LSP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiagnosticReport {
    diagnostics: Vec<SemanticDiagnostic>,
    outcomes: Vec<SemanticDiagnosticOutcome>,
    status: SemanticDiagnosticReportStatus,
}

impl Default for SemanticDiagnosticReport {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            outcomes: Vec::new(),
            status: SemanticDiagnosticReportStatus::Complete,
        }
    }
}

impl SemanticDiagnosticReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert diagnostics that a language collector proved absent from the
    /// complete workspace-local lexical surface it checked.
    pub fn from_workspace_absences(
        file: &ProjectFile,
        diagnostics: Vec<SemanticDiagnostic>,
    ) -> Self {
        let mut report = Self::new();
        for diagnostic in diagnostics {
            let range = diagnostic.range;
            report.push_absent(
                SemanticAbsenceProof {
                    range,
                    domain: SemanticDiagnosticDomain::LexicalScope {
                        file: file.rel_path().to_path_buf(),
                        range,
                    },
                    boundary: BoundaryStatus::WorkspaceLocal,
                },
                diagnostic,
            );
        }
        report
    }

    pub fn push_resolved(&mut self, range: Range, boundary: BoundaryStatus) {
        self.outcomes
            .push(SemanticDiagnosticOutcome::Resolved { range, boundary });
    }

    pub fn push_ambiguous(&mut self, range: Range, boundaries: Vec<BoundaryStatus>) {
        assert!(!boundaries.is_empty(), "ambiguity must name a boundary");
        self.outcomes
            .push(SemanticDiagnosticOutcome::Ambiguous { range, boundaries });
    }

    pub fn push_absent(&mut self, proof: SemanticAbsenceProof, diagnostic: SemanticDiagnostic) {
        assert!(
            matches!(
                proof.boundary,
                BoundaryStatus::WorkspaceLocal | BoundaryStatus::ExternalIndexed
            ),
            "absence proof requires a complete boundary"
        );
        assert_eq!(
            proof.range, diagnostic.range,
            "absence proof and diagnostic must identify the same source range"
        );
        self.outcomes.push(SemanticDiagnosticOutcome::Absent(proof));
        self.diagnostics.push(diagnostic);
    }

    pub fn push_incomplete(
        &mut self,
        range: Option<Range>,
        reasons: Vec<SemanticDiagnosticIncompleteReason>,
    ) {
        assert!(
            !reasons.is_empty(),
            "incomplete outcome must state a reason"
        );
        self.outcomes
            .push(SemanticDiagnosticOutcome::Incomplete { range, reasons });
        self.status = SemanticDiagnosticReportStatus::Incomplete;
    }

    pub fn diagnostics(&self) -> &[SemanticDiagnostic] {
        &self.diagnostics
    }

    pub fn outcomes(&self) -> &[SemanticDiagnosticOutcome] {
        &self.outcomes
    }

    pub fn status(&self) -> SemanticDiagnosticReportStatus {
        self.status
    }

    pub fn into_diagnostics(self) -> Vec<SemanticDiagnostic> {
        self.diagnostics
    }
}

impl std::ops::Deref for SemanticDiagnosticReport {
    type Target = [SemanticDiagnostic];

    fn deref(&self) -> &Self::Target {
        self.diagnostics()
    }
}

impl IntoIterator for SemanticDiagnosticReport {
    type Item = SemanticDiagnostic;
    type IntoIter = std::vec::IntoIter<SemanticDiagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.diagnostics.into_iter()
    }
}

#[cfg(test)]
mod semantic_diagnostic_report_tests {
    use super::*;

    fn range(start_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte: start_byte + 1,
            start_line: 1,
            end_line: 1,
        }
    }

    fn diagnostic(range: Range) -> SemanticDiagnostic {
        SemanticDiagnostic {
            range,
            source: "test",
            kind: "unrecognized_symbol",
            message: "Unrecognized symbol `Missing`".to_string(),
        }
    }

    #[test]
    fn report_emits_only_a_diagnostic_with_complete_absence_proof() {
        let location = range(2);
        let mut report = SemanticDiagnosticReport::new();
        report.push_resolved(location, BoundaryStatus::ExternalIndexed);
        report.push_ambiguous(
            location,
            vec![
                BoundaryStatus::WorkspaceLocal,
                BoundaryStatus::ExternalIndexed,
            ],
        );
        report.push_incomplete(
            Some(location),
            vec![SemanticDiagnosticIncompleteReason::Cancelled],
        );

        assert!(report.diagnostics().is_empty());
        assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);

        report.push_absent(
            SemanticAbsenceProof {
                range: location,
                domain: SemanticDiagnosticDomain::Type {
                    name: "example.Owner".to_string(),
                },
                boundary: BoundaryStatus::ExternalIndexed,
            },
            diagnostic(location),
        );

        assert_eq!(report.diagnostics(), &[diagnostic(location)]);
        assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
        assert_eq!(report.outcomes().len(), 4);
        assert!(matches!(
            report.outcomes().last(),
            Some(SemanticDiagnosticOutcome::Absent(proof))
                if proof.boundary == BoundaryStatus::ExternalIndexed
        ));
    }

    #[test]
    fn report_retains_each_typed_incomplete_reason_without_an_error() {
        let reasons = vec![
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
            },
            SemanticDiagnosticIncompleteReason::StaleGeneration {
                expected: 4,
                actual: 3,
            },
            SemanticDiagnosticIncompleteReason::Cancelled,
            SemanticDiagnosticIncompleteReason::Truncated,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "macro expansion".to_string(),
            },
            SemanticDiagnosticIncompleteReason::DynamicBehavior {
                detail: "runtime member".to_string(),
            },
            SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                detail: "pack activation unavailable".to_string(),
            },
            SemanticDiagnosticIncompleteReason::CorruptSemanticPack {
                detail: "invalid manifest".to_string(),
            },
            SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                detail: "generated sources are not indexed".to_string(),
            },
        ];
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(Some(range(7)), reasons.clone());

        assert!(report.diagnostics().is_empty());
        assert_eq!(
            report.outcomes(),
            &[SemanticDiagnosticOutcome::Incomplete {
                range: Some(range(7)),
                reasons,
            }]
        );
    }

    #[test]
    fn workspace_conversion_records_the_checked_lexical_domain() {
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "src/Main.java");
        let location = range(11);
        let report =
            SemanticDiagnosticReport::from_workspace_absences(&file, vec![diagnostic(location)]);

        assert_eq!(report.diagnostics(), &[diagnostic(location)]);
        assert_eq!(report.status(), SemanticDiagnosticReportStatus::Complete);
        assert!(matches!(
            report.outcomes(),
            [SemanticDiagnosticOutcome::Absent(SemanticAbsenceProof {
                range,
                domain: SemanticDiagnosticDomain::LexicalScope { file, range: domain_range },
                boundary: BoundaryStatus::WorkspaceLocal,
            })] if *range == location
                && file == &PathBuf::from("src/Main.java")
                && *domain_range == location
        ));
    }

    #[test]
    #[should_panic(expected = "absence proof and diagnostic must identify the same source range")]
    fn report_rejects_an_error_without_matching_absence_evidence() {
        let mut report = SemanticDiagnosticReport::new();
        report.push_absent(
            SemanticAbsenceProof {
                range: range(1),
                domain: SemanticDiagnosticDomain::Module {
                    name: "example".to_string(),
                },
                boundary: BoundaryStatus::WorkspaceLocal,
            },
            diagnostic(range(2)),
        );
    }

    #[test]
    #[should_panic(expected = "absence proof requires a complete boundary")]
    fn report_rejects_absence_at_an_unknown_boundary() {
        let location = range(3);
        let mut report = SemanticDiagnosticReport::new();
        report.push_absent(
            SemanticAbsenceProof {
                range: location,
                domain: SemanticDiagnosticDomain::Package {
                    name: "unknown.external".to_string(),
                },
                boundary: BoundaryStatus::ExternalUnknown,
            },
            diagnostic(location),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeclarationKind {
    Parameter,
    ReceiverParameter,
    LocalVariable,
    CatchParameter,
    EnhancedForVariable,
    LambdaParameter,
    PatternVariable,
    ResourceVariable,
}

impl DeclarationKind {
    /// Stable snake_case label for wire output and rendering.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Parameter => "parameter",
            Self::ReceiverParameter => "receiver_parameter",
            Self::LocalVariable => "local_variable",
            Self::CatchParameter => "catch_parameter",
            Self::EnhancedForVariable => "enhanced_for_variable",
            Self::LambdaParameter => "lambda_parameter",
            Self::PatternVariable => "pattern_variable",
            Self::ResourceVariable => "resource_variable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclarationInfo {
    pub identifier: String,
    pub kind: DeclarationKind,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeBaseMetrics {
    pub file_count: usize,
    pub declaration_count: usize,
}

impl CodeBaseMetrics {
    pub fn new(file_count: usize, declaration_count: usize) -> Self {
        Self {
            file_count,
            declaration_count,
        }
    }
}

pub fn metrics_from_declarations(
    declarations: impl IntoIterator<Item = CodeUnit>,
) -> CodeBaseMetrics {
    let declarations: Vec<CodeUnit> = declarations.into_iter().collect();
    let file_count = declarations
        .iter()
        .map(|cu| cu.source().clone())
        .collect::<BTreeSet<_>>()
        .len();
    CodeBaseMetrics::new(file_count, declarations.len())
}

#[cfg(test)]
mod package_anchor_tests {
    use super::*;

    fn anchored_unit() -> CodeUnit {
        let source = ProjectFile::new(PathBuf::from("/repo"), PathBuf::from("src/describe.rs"));
        CodeUnit::with_signature(
            source,
            CodeUnitType::Function,
            "demo",
            "JsError.describe",
            Some("fn describe()".to_string()),
            false,
        )
        .with_package_anchor(PackageAnchor::CrateRoot)
    }

    #[test]
    fn rebuilders_preserve_the_package_anchor() {
        let unit = anchored_unit();
        assert_eq!(unit.package_anchor(), Some(PackageAnchor::CrateRoot));

        let stripped = unit.without_signature();
        assert_eq!(stripped.signature(), None);
        assert_eq!(stripped.package_anchor(), Some(PackageAnchor::CrateRoot));

        let synthetic = unit.with_synthetic(true);
        assert!(synthetic.is_synthetic());
        assert_eq!(synthetic.package_anchor(), Some(PackageAnchor::CrateRoot));

        // Chained rebuilds keep it too, including a non-unit-variant anchor.
        let popped = unit
            .clone()
            .with_package_anchor(PackageAnchor::OwnModule { pop: 2 })
            .with_synthetic(true)
            .without_signature();
        assert_eq!(
            popped.package_anchor(),
            Some(PackageAnchor::OwnModule { pop: 2 })
        );
        assert_eq!(popped.fq(), unit.fq());
        assert_eq!(popped.package_name(), unit.package_name());
    }

    #[test]
    fn units_default_to_the_adapter_anchor() {
        let source = ProjectFile::new(PathBuf::from("/repo"), PathBuf::from("src/lib.rs"));
        let unit = CodeUnit::new(source, CodeUnitType::Class, "demo", "JsError");
        assert_eq!(unit.package_anchor(), None);
        assert_eq!(unit.without_signature().package_anchor(), None);
    }
}

#[cfg(test)]
mod structured_type_identity_tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash(identity: &StructuredTypeIdentity) -> u64 {
        let mut hasher = DefaultHasher::new();
        identity.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn flat_identity_operations_are_stack_safe_on_deep_types() {
        std::thread::Builder::new()
            .name("flat-structured-type".to_string())
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut builder = StructuredTypeIdentityBuilder::default();
                let name = StructuredTypeName::new(
                    vec!["example.com/service".to_string(), "Service".to_string()],
                    Vec::new(),
                    false,
                )
                .expect("structured name");
                let mut root = builder.named(name).expect("named node");
                for _ in 1..MAX_STRUCTURED_TYPE_IDENTITY_NODES {
                    root = builder.pointer(root).expect("pointer node");
                }
                assert!(
                    builder.pointer(root).is_none(),
                    "builder must reject identities beyond the fixed admission cap"
                );
                let identity = builder.finish(root).expect("deep flat identity");
                assert!(
                    identity.clone().wrap_pointer().is_none(),
                    "finished identities must preserve the same admission cap"
                );

                let cloned = identity.clone();
                assert_eq!(identity, cloned);
                assert_eq!(hash(&identity), hash(&cloned));

                let bytes = bincode::serialize(&identity).expect("serialize flat identity");
                let decoded: StructuredTypeIdentity =
                    bincode::deserialize(&bytes).expect("deserialize flat identity");
                assert_eq!(identity, decoded);
                assert_eq!(hash(&identity), hash(&decoded));

                let metadata = SignatureMetadata::new("deep", Vec::new())
                    .with_return_type_identity(Some(decoded));
                let bytes = bincode::serialize(&metadata).expect("serialize signature metadata");
                let decoded: SignatureMetadata =
                    bincode::deserialize(&bytes).expect("deserialize signature metadata");
                assert_eq!(metadata, decoded);
            })
            .expect("spawn small-stack thread")
            .join()
            .expect("flat structured-type operations must not overflow");
    }

    #[test]
    fn bounded_regression_shared_child_dags_compare_and_hash_in_linear_arena_work() {
        const DEPTH: usize = 80;

        let leaf_name = || {
            StructuredTypeName::new(vec!["Leaf".to_string()], Vec::new(), false)
                .expect("structured leaf")
        };

        let mut shared_builder = StructuredTypeIdentityBuilder::default();
        let mut shared_root = shared_builder.named(leaf_name()).expect("shared leaf node");
        for _ in 0..DEPTH {
            shared_root = shared_builder
                .map(shared_root, shared_root)
                .expect("shared map node");
        }
        let shared = shared_builder
            .finish(shared_root)
            .expect("shared-child identity");

        // Build the same expanded shape with one level represented by two
        // distinct-but-equivalent subgraphs. Equality and hashing must not
        // depend on arena sharing.
        let mut split_builder = StructuredTypeIdentityBuilder::default();
        let left_leaf = split_builder.named(leaf_name()).expect("left leaf");
        let right_leaf = split_builder.named(leaf_name()).expect("right leaf");
        let left = split_builder
            .map(left_leaf, left_leaf)
            .expect("left shared map");
        let right = split_builder
            .map(right_leaf, right_leaf)
            .expect("right shared map");
        let mut split_root = split_builder.map(left, right).expect("split map root");
        for _ in 2..DEPTH {
            split_root = split_builder
                .map(split_root, split_root)
                .expect("shared split-map node");
        }
        let split = split_builder
            .finish(split_root)
            .expect("differently shared identity");

        assert_eq!(shared, split);
        assert_eq!(hash(&shared), hash(&split));

        let mut visits = 0usize;
        assert_eq!(
            shared.structurally_eq_with(&split, || {
                visits += 1;
                true
            }),
            Some(true)
        );
        assert_eq!(
            visits,
            shared.nodes.len() + split.nodes.len(),
            "bounded equality must inspect each reachable arena node once"
        );
    }

    #[test]
    fn deserialization_rejects_structured_identity_above_node_cap() {
        let name = StructuredTypeName::new(vec!["Service".to_string()], Vec::new(), false)
            .expect("structured name");
        let mut nodes = Vec::with_capacity(MAX_STRUCTURED_TYPE_IDENTITY_NODES + 1);
        nodes.push(StructuredTypeNode::Named(name));
        for index in 1..=MAX_STRUCTURED_TYPE_IDENTITY_NODES {
            nodes.push(StructuredTypeNode::Pointer(StructuredTypeNodeId(
                u32::try_from(index - 1).expect("bounded test index"),
            )));
        }
        let wire = StructuredTypeIdentityWire {
            nodes: BoundedStructuredTypeNodes(nodes),
            root: StructuredTypeNodeId(
                u32::try_from(MAX_STRUCTURED_TYPE_IDENTITY_NODES).expect("bounded test root"),
            ),
        };
        let bytes = bincode::serialize(&wire).expect("serialize oversized identity");

        assert!(
            bincode::deserialize::<StructuredTypeIdentity>(&bytes).is_err(),
            "deserialization must reject the oversized node sequence before accepting it"
        );
    }

    #[test]
    fn resource_bound_rejects_oversized_structured_name_length_prefixes() {
        let oversized_component_count =
            u64::try_from(MAX_STRUCTURED_TYPE_NAME_COMPONENTS + 1).unwrap();
        assert!(
            bincode::deserialize::<StructuredTypeName>(&oversized_component_count.to_le_bytes())
                .is_err(),
            "the path component count must be rejected from its length prefix"
        );

        let oversized_string_bytes =
            u64::try_from(MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES + 1).unwrap();
        let mut oversized_path_string = Vec::new();
        oversized_path_string.extend_from_slice(&1_u64.to_le_bytes());
        oversized_path_string.extend_from_slice(&oversized_string_bytes.to_le_bytes());
        assert!(
            bincode::deserialize::<StructuredTypeName>(&oversized_path_string).is_err(),
            "a path string must be rejected from its length prefix before reading its payload"
        );

        let mut oversized_lexical_string = Vec::new();
        oversized_lexical_string.extend_from_slice(&1_u64.to_le_bytes());
        oversized_lexical_string.extend_from_slice(&1_u64.to_le_bytes());
        oversized_lexical_string.push(b'S');
        oversized_lexical_string.extend_from_slice(&1_u64.to_le_bytes());
        oversized_lexical_string.extend_from_slice(&oversized_string_bytes.to_le_bytes());
        assert!(
            bincode::deserialize::<StructuredTypeName>(&oversized_lexical_string).is_err(),
            "a lexical-scope string must be rejected from its length prefix before reading its payload"
        );
    }

    #[test]
    fn resource_bound_rejects_oversized_generic_argument_length_prefix() {
        let mut builder = StructuredTypeIdentityBuilder::default();
        let name = StructuredTypeName::new(vec!["Service".to_string()], Vec::new(), false)
            .expect("structured name");
        let base = builder.named(name).expect("named node");
        let generic = builder.generic(base, Vec::new()).expect("generic node");
        let identity = builder.finish(generic).expect("structured identity");
        let mut bytes = bincode::serialize(&identity).expect("serialize generic identity");

        let argument_length_offset = bytes
            .len()
            .checked_sub(std::mem::size_of::<u64>() + std::mem::size_of::<u32>())
            .expect("generic identity wire suffix");
        assert_eq!(
            &bytes[argument_length_offset..argument_length_offset + std::mem::size_of::<u64>()],
            &0_u64.to_le_bytes(),
            "the empty generic argument vector precedes the root node id"
        );
        bytes[argument_length_offset..argument_length_offset + std::mem::size_of::<u64>()]
            .copy_from_slice(
                &u64::try_from(MAX_STRUCTURED_TYPE_IDENTITY_EDGES + 1)
                    .unwrap()
                    .to_le_bytes(),
            );

        assert!(
            bincode::deserialize::<StructuredTypeIdentity>(&bytes).is_err(),
            "the generic argument vector must be rejected from its length prefix"
        );
    }

    #[test]
    fn resource_bound_preserves_existing_generic_bincode_wire_roundtrip() {
        let mut builder = StructuredTypeIdentityBuilder::default();
        let base = builder
            .named(
                StructuredTypeName::new(vec!["Result".to_string()], Vec::new(), false)
                    .expect("base name"),
            )
            .expect("base node");
        let argument = builder
            .named(
                StructuredTypeName::new(
                    vec!["example".to_string(), "Service".to_string()],
                    vec!["scope".to_string()],
                    false,
                )
                .expect("argument name"),
            )
            .expect("argument node");
        let generic = builder.generic(base, vec![argument]).expect("generic node");
        let identity = builder.finish(generic).expect("structured identity");

        let bytes = bincode::serialize(&identity).expect("serialize identity");
        let decoded: StructuredTypeIdentity =
            bincode::deserialize(&bytes).expect("deserialize identity");
        assert_eq!(decoded, identity);
    }

    #[test]
    fn rerooted_container_identity_compares_by_reachable_shape() {
        let service =
            StructuredTypeName::new(vec!["Service".to_string()], Vec::new(), false).unwrap();
        let key = StructuredTypeName::new(vec!["string".to_string()], Vec::new(), false).unwrap();

        let mut map_builder = StructuredTypeIdentityBuilder::default();
        let key_id = map_builder.named(key).unwrap();
        let value_id = map_builder.named(service.clone()).unwrap();
        let map_id = map_builder.map(key_id, value_id).unwrap();
        let value = map_builder
            .finish(map_id)
            .unwrap()
            .into_container_element_with(|| true)
            .unwrap();

        let mut named_builder = StructuredTypeIdentityBuilder::default();
        let named_id = named_builder.named(service).unwrap();
        let named = named_builder.finish(named_id).unwrap();

        assert_eq!(value, named);
        assert_eq!(hash(&value), hash(&named));
    }
}

#[cfg(test)]
mod claude_plugin_lsp_manifest_tests {
    use super::Language;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;

    #[test]
    fn claude_plugin_maps_every_analyzable_extension_to_bifrost_lsp() {
        let manifest_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins/bifrost-agent/.lsp.json");
        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&manifest_path).expect("read Claude LSP manifest"),
        )
        .expect("parse Claude LSP manifest");
        let actual: BTreeMap<String, String> =
            serde_json::from_value(manifest["bifrost"]["extensionToLanguage"].clone())
                .expect("Claude LSP manifest extensionToLanguage object");

        let expected = Language::ANALYZABLE
            .into_iter()
            .flat_map(|language| {
                language.extensions().iter().map(move |extension| {
                    let language_id = match *extension {
                        "c" | "h" => "c",
                        "jsx" => "javascriptreact",
                        "tsx" => "typescriptreact",
                        _ => language.config_label(),
                    };
                    (format!(".{extension}"), language_id.to_string())
                })
            })
            .collect();

        assert_eq!(actual, expected);
    }
}

#[cfg(all(test, windows))]
mod path_tests {
    use super::*;

    #[test]
    fn project_file_normalizes_ordinary_and_verbatim_roots_equally() {
        let ordinary = ProjectFile::new(
            PathBuf::from(r"C:\Users\runner\repo"),
            PathBuf::from(r"src\..\A.java"),
        );
        let verbatim = ProjectFile::new(
            PathBuf::from(r"\\?\C:\Users\runner\repo"),
            PathBuf::from("A.java"),
        );
        assert_eq!(ordinary, verbatim);
    }

    #[test]
    fn project_file_normalizes_ordinary_and_verbatim_unc_roots_equally() {
        let ordinary = ProjectFile::new(
            PathBuf::from(r"\\server\share\repo"),
            PathBuf::from("A.java"),
        );
        let verbatim = ProjectFile::new(
            PathBuf::from(r"\\?\UNC\server\share\repo"),
            PathBuf::from("A.java"),
        );
        assert_eq!(ordinary, verbatim);
    }
}
