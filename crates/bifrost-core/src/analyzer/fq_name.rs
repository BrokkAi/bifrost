//! Interned, kind-tagged qualified names (`FqName`).
//!
//! Bifrost historically identified every declaration by a plain string
//! (`package_name` + `short_name` on [`crate::analyzer::CodeUnit`]). The
//! structure of that string — where one segment ends and the next begins, and
//! what *kind* of segment it is — was not recorded anywhere, so every consumer
//! re-inferred it by splitting on a guessed set of delimiters. That inference
//! is a recurring bug factory (issues 1128/1131/1162/1163).
//!
//! An [`FqName`] records the structure once, at construction, where the
//! language extractor knows exactly what it is emitting. It is an ordered
//! (root-to-leaf) list of [`SegmentId`]s. Each `SegmentId` interns a
//! `(text, kind)` pair, so equality and prefix checks are pure integer
//! comparisons and the segment boundaries are never re-guessed.
//!
//! The interner is process-global and grow-only (see [`segment_interner`]);
//! `SegmentId`s are therefore process-local and must never be persisted (the
//! store persists segment text + kind, never IDs).

use smallvec::SmallVec;
use std::sync::{OnceLock, RwLock};

use crate::analyzer::Language;
use crate::hash::HashMap;

/// What a qualified-name segment denotes. Baked into the interned entry rather
/// than stored in a parallel per-position field, so an `FqName` stays a single
/// small vector of integers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SegmentKind {
    /// A file/directory step. May contain literal dots (e.g. `github.com`).
    Path,
    /// A namespace / package / module.
    Package,
    /// A class, struct, enum, trait, interface, or object.
    Type,
    /// A nested-scope boundary spelled with a literal `$` rather than `.`:
    /// Scala companion objects, and (reused for the same rendering, not a new
    /// per-language meaning) Python's `$`-joined local classes/functions and
    /// Ruby/PHP's `$`-joined nested types. Renders with `$` regardless of the
    /// preceding segment's kind.
    Companion,
    /// A type or scope joined to its parent with a literal `$` (python/php
    /// nested types, python local functions, ruby namespace chains, and --
    /// convention-compatible -- cpp/java `Outer$Inner` nested classes). The
    /// `$` is a JOIN rendered by `separator` before this segment, unlike
    /// [`SegmentKind::Companion`], whose `$` is a suffix on the segment's own
    /// name (scala objects).
    Nested,
    /// A function, method, field, const, alias, or macro.
    Member,
    /// A segment whose denotation is not known from its spelling — the kind
    /// assigned to every segment of a *user-supplied* symbol path parsed at the
    /// MCP input edge (see `analyzer::symbol_lookup::parse_symbol_path_fq` in
    /// `brokk-bifrost-analysis`). Users type
    /// spellings, not kinds, so input segments are matched kind-insensitively
    /// against extracted names; `Unknown` records "no kind claim". It renders
    /// with an ordinary `.` join (the default), so an input `FqName` renders to
    /// exactly the canonical `.`-joined spelling the string index is keyed by —
    /// which is why M2's consumers can match input against the string-keyed
    /// `definitions` index by rendering, without a kind-aware compare. See the
    /// Decision Log entry in `.agents/plans/fqname-interned-segments.md`.
    Unknown,
}

impl SegmentKind {
    /// Stable on-disk tag for the cache's `code_units.fq_segments` blob. These
    /// numbers are a persistence contract: never renumber an existing variant
    /// (append new ones), or previously-cached rows would decode to the wrong
    /// kind. The analysis-epoch salt (`src/analyzer/store/epoch.rs`) guards
    /// against a format change slipping past by forcing re-extraction, but the
    /// tags themselves must stay stable so a mixed-vintage cache never
    /// misinterprets a byte.
    pub(crate) const fn persist_tag(self) -> u8 {
        match self {
            SegmentKind::Path => 0,
            SegmentKind::Package => 1,
            SegmentKind::Type => 2,
            SegmentKind::Companion => 3,
            SegmentKind::Nested => 4,
            SegmentKind::Member => 5,
            SegmentKind::Unknown => 6,
        }
    }

    /// Stable, human-readable name for the kind. Used by the debug/test-only
    /// `CodeUnit::fq_segments_debug` cross-check so a test can compare kinds
    /// without the (crate-private) `SegmentKind` type leaking into `tests/`.
    #[cfg(any(test, debug_assertions))]
    pub const fn name(self) -> &'static str {
        match self {
            SegmentKind::Path => "Path",
            SegmentKind::Package => "Package",
            SegmentKind::Type => "Type",
            SegmentKind::Companion => "Companion",
            SegmentKind::Nested => "Nested",
            SegmentKind::Member => "Member",
            SegmentKind::Unknown => "Unknown",
        }
    }

    /// Inverse of [`Self::persist_tag`]; `None` for an unrecognized tag byte.
    pub(crate) const fn from_persist_tag(tag: u8) -> Option<SegmentKind> {
        match tag {
            0 => Some(SegmentKind::Path),
            1 => Some(SegmentKind::Package),
            2 => Some(SegmentKind::Type),
            3 => Some(SegmentKind::Companion),
            4 => Some(SegmentKind::Nested),
            5 => Some(SegmentKind::Member),
            6 => Some(SegmentKind::Unknown),
            _ => None,
        }
    }
}

/// Interned `(text, kind)` pair. Process-local; never persisted.
///
/// The `u32` encodes both the owning interner shard and the entry index within
/// that shard (`index * SHARD_COUNT + shard`), so a bare `SegmentId` can be
/// resolved without a side table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SegmentId(u32);

/// The qualified name. Ordered root-to-leaf. Comparisons are integer memcmp.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct FqName {
    segments: SmallVec<[SegmentId; 8]>,
}

impl FqName {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    // `parent`, `segments`, and `display_native` are wired into the M2 shared
    // resolvers (owner-chain pop, enclosing-scope composition). `len`, `last`,
    // and `starts_with` round out the consumer-facing surface and are
    // unit-tested so the API is settled, but no production caller reads them
    // until later milestones; the allow keeps the tree green under `-D warnings`
    // without a blanket module allow.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn push(&mut self, id: SegmentId) {
        self.segments.push(id);
    }

    /// Builder-style push, convenient when threading a parent's name into a
    /// child at a `CodeUnit` construction site.
    pub fn with_pushed(mut self, id: SegmentId) -> Self {
        self.segments.push(id);
        self
    }

    /// The name with its final segment removed, or `None` if empty. Allocates
    /// only the SmallVec copy, never a string.
    pub fn parent(&self) -> Option<FqName> {
        if self.segments.is_empty() {
            return None;
        }
        Some(FqName {
            segments: SmallVec::from_slice(&self.segments[..self.segments.len() - 1]),
        })
    }

    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub fn last(&self) -> Option<SegmentId> {
        self.segments.last().copied()
    }

    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub fn starts_with(&self, prefix: &FqName) -> bool {
        self.segments.starts_with(&prefix.segments)
    }

    pub fn segments(&self) -> &[SegmentId] {
        &self.segments
    }

    /// Serialize to the compact, self-describing byte blob persisted in the
    /// cache's `code_units.fq_segments` column. Interner IDs are process-local
    /// and are NEVER written; each segment's `(text, kind)` pair is resolved
    /// through `interner` and encoded as a one-byte kind tag, a little-endian
    /// `u32` text length, then the UTF-8 text. Segment text is free-form (it can
    /// contain `.`, `::`, `$`, `#`), so the explicit length prefix keeps decode
    /// unambiguous with zero escaping. An empty `FqName` encodes to an empty
    /// `Vec` (persisted as SQL NULL). See `FqName::decode_segments` for the
    /// inverse and `migrations/cache/0012-fq-segments.sql` for the column.
    pub fn encode_segments(&self, interner: &SegmentInterner) -> Vec<u8> {
        let mut out = Vec::new();
        for &id in &self.segments {
            let (text, kind) = interner.resolve(id);
            out.push(kind.persist_tag());
            out.extend_from_slice(&(text.len() as u32).to_le_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        out
    }

    /// Re-intern the segments encoded by [`Self::encode_segments`] into a fresh
    /// `FqName` bound to this process's interner (IDs differ every run, so the
    /// text+kind are re-interned rather than trusted from disk). An empty slice
    /// yields an empty `FqName`. Returns an error string on a malformed blob.
    pub fn decode_segments(bytes: &[u8], interner: &SegmentInterner) -> Result<FqName, String> {
        let mut fq = FqName::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let tag = bytes[offset];
            offset += 1;
            let kind = SegmentKind::from_persist_tag(tag)
                .ok_or_else(|| format!("unknown fq segment kind tag {tag}"))?;
            let len_end = offset
                .checked_add(4)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| "truncated fq segment length prefix".to_string())?;
            let len = u32::from_le_bytes(bytes[offset..len_end].try_into().unwrap()) as usize;
            offset = len_end;
            let text_end = offset
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| "truncated fq segment text".to_string())?;
            let text = std::str::from_utf8(&bytes[offset..text_end])
                .map_err(|err| format!("invalid utf8 in fq segment text: {err}"))?;
            offset = text_end;
            fq.push(interner.intern(text, kind));
        }
        Ok(fq)
    }

    /// Append every segment of `tail` after this name's segments.
    pub fn extend_from(&mut self, tail: &FqName) {
        self.segments.extend_from_slice(&tail.segments);
    }

    /// The suffix of this name after its first `prefix_len` segments, as an owned
    /// `FqName`. Used at persistence time to keep only the content-stable
    /// `short_name` tail (the path-derived package prefix is rebuilt on load; see
    /// `package_prefix_fq`).
    pub fn suffix_from(&self, prefix_len: usize) -> FqName {
        FqName {
            segments: SmallVec::from_slice(&self.segments[prefix_len.min(self.segments.len())..]),
        }
    }

    /// Canonical display: `.`-joined, `/` between adjacent [`SegmentKind::Path`]
    /// segments (so import-path heads such as `github.com/foo/bar` round-trip),
    /// and a trailing `$` suffix on each [`SegmentKind::Companion`] segment (so
    /// Scala object spellings such as `LocalScheduler$` and `Outer$.Inner$`
    /// round-trip). This reproduces exactly today's user-facing `fq_name()`
    /// convention, so display output does not change.
    ///
    /// The M1 equivalence check renders natively (see [`Self::display_native`]);
    /// this canonical form is exercised by the module unit tests now and becomes
    /// the user-facing rendering surface in M2, so it is allowed to be otherwise
    /// unused in the meantime (same rationale as `len`/`parent`/... above).
    #[allow(dead_code)]
    pub fn display(&self, interner: &SegmentInterner) -> String {
        self.render(interner, None)
    }

    /// Native display: language-specific separators (`::` between adjacent C++
    /// [`SegmentKind::Package`] segments, `$` between adjacent C++ nested-class
    /// [`SegmentKind::Type`] segments) for surfaces that render native
    /// spellings — including the M1 equivalence check in
    /// [`crate::analyzer::CodeUnit::with_signature_and_fq`].
    pub fn display_native(&self, lang: Language, interner: &SegmentInterner) -> String {
        self.render(interner, Some(lang))
    }

    fn render(&self, interner: &SegmentInterner, native: Option<Language>) -> String {
        let mut out = String::new();
        let mut prev: Option<SegmentKind> = None;
        for &id in &self.segments {
            let (text, kind) = interner.resolve(id);
            if let Some(prev_kind) = prev {
                out.push_str(separator(prev_kind, kind, native));
            }
            out.push_str(text);
            // A Scala `object` segment is spelled with a trailing `$` *suffix*
            // on its own name (`LocalScheduler$`, `Outer$.Inner$`), joined to
            // neighbours with an ordinary `.`. The `$` is part of this segment,
            // not a separator, so it is emitted here rather than by `separator`.
            if kind == SegmentKind::Companion {
                out.push('$');
            }
            prev = Some(kind);
        }
        out
    }
}

/// The separator that renders between a segment of kind `prev` and a following
/// segment of kind `cur`. `native` selects language-specific spellings.
fn separator(prev: SegmentKind, cur: SegmentKind, native: Option<Language>) -> &'static str {
    if prev == SegmentKind::Path && cur == SegmentKind::Path {
        return "/";
    }
    // A Nested segment is BY DEFINITION `$`-joined to whatever precedes it,
    // in both canonical and native renderings (python/php nested types, ruby
    // chains, cpp/java nested classes once migrated onto this kind).
    if cur == SegmentKind::Nested {
        return "$";
    }
    if native == Some(Language::Cpp) {
        // C++'s legacy string spelling keeps a `::`-joined namespace (Package)
        // head, joined to the terminal member with `.` (issue #1163). Nested
        // classes are `$`-joined too, but that is handled generically by the
        // `Nested` rule above (see `cpp_push_type_chain` in
        // `src/analyzer/cpp/declarations.rs`), not by a cpp-specific rule here.
        if prev == SegmentKind::Package && cur == SegmentKind::Package {
            return "::";
        }
    }
    "."
}

/// Number of interner shards. Extraction is file-parallel, so `intern` spreads
/// contention across independent locks; each shard owns a disjoint slice of the
/// `SegmentId` space.
const SHARD_COUNT: usize = 16;

struct Shard {
    /// `text -> [(kind, id)]`. Keyed by owned `String` so lookups on the hot
    /// (hit) path borrow a `&str` without allocating.
    by_text: HashMap<String, SmallVec<[(SegmentKind, SegmentId); 2]>>,
    /// Local index -> `(leaked text, kind)`. The text is leaked once on first
    /// insert so [`SegmentInterner::resolve`] can hand back a `&str` that
    /// outlives any lock guard; the interner is grow-only for the process
    /// lifetime, so this is bounded by the segment vocabulary.
    entries: Vec<(&'static str, SegmentKind)>,
}

/// Sharded, concurrent interner of `(text, kind)` pairs.
pub struct SegmentInterner {
    shards: [RwLock<Shard>; SHARD_COUNT],
}

impl SegmentInterner {
    fn new() -> Self {
        SegmentInterner {
            shards: std::array::from_fn(|_| {
                RwLock::new(Shard {
                    by_text: HashMap::default(),
                    entries: Vec::new(),
                })
            }),
        }
    }

    fn shard_of(text: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        text.hash(&mut hasher);
        (hasher.finish() as usize) % SHARD_COUNT
    }

    fn encode(shard: usize, local: usize) -> SegmentId {
        SegmentId((local * SHARD_COUNT + shard) as u32)
    }

    pub fn intern(&self, text: &str, kind: SegmentKind) -> SegmentId {
        let shard_idx = Self::shard_of(text);
        // Fast path: an existing entry can be found under a read lock.
        {
            let shard = self.shards[shard_idx].read().unwrap();
            if let Some(slots) = shard.by_text.get(text) {
                for &(entry_kind, id) in slots {
                    if entry_kind == kind {
                        return id;
                    }
                }
            }
        }
        // Slow path: insert under a write lock, re-checking for a racing writer.
        let mut shard = self.shards[shard_idx].write().unwrap();
        if let Some(slots) = shard.by_text.get(text) {
            for &(entry_kind, id) in slots {
                if entry_kind == kind {
                    return id;
                }
            }
        }
        let local = shard.entries.len();
        let id = Self::encode(shard_idx, local);
        let leaked: &'static str = Box::leak(text.to_owned().into_boxed_str());
        shard.entries.push((leaked, kind));
        shard
            .by_text
            .entry(text.to_owned())
            .or_default()
            .push((kind, id));
        id
    }

    pub fn resolve(&self, id: SegmentId) -> (&str, SegmentKind) {
        let shard_idx = (id.0 as usize) % SHARD_COUNT;
        let local = (id.0 as usize) / SHARD_COUNT;
        let shard = self.shards[shard_idx].read().unwrap();
        let (text, kind) = shard.entries[local];
        // `text` is `&'static str`; returning it under `&self`'s lifetime is a
        // safe subtyping shrink, and it outlives the dropped read guard.
        (text, kind)
    }

    /// The separator that would render between two already-interned segments in
    /// language `lang`'s native spelling. Exposed so the shrinking-scope
    /// resolver can reproduce the legacy dot-only prefix walk exactly: it
    /// descends across a boundary only where that boundary renders as a literal
    /// `.` (never `::` in C++'s namespace head, `/` between path components, or
    /// `$` before a nested segment), which is what keeps a `::`-headed C++
    /// namespace scope from being descended (issue #1163 stays pinned until M4).
    pub fn separator_between(
        &self,
        prev: SegmentId,
        cur: SegmentId,
        lang: Language,
    ) -> &'static str {
        let (_, prev_kind) = self.resolve(prev);
        let (_, cur_kind) = self.resolve(cur);
        separator(prev_kind, cur_kind, Some(lang))
    }
}

/// The process-global interner.
///
/// Decided in M0: a single process-global interner rather than one per
/// workspace. Threading a per-workspace interner through every `CodeUnit`
/// constructor across eleven languages is a large mechanical cost with no
/// correctness benefit while the legacy strings remain authoritative; entries
/// are tiny and text-deduplicated, and the plan explicitly permits this.
pub fn segment_interner() -> &'static SegmentInterner {
    static INTERNER: OnceLock<SegmentInterner> = OnceLock::new();
    INTERNER.get_or_init(SegmentInterner::new)
}

/// Rebuild the package-prefix segments of a qualified name from its already
/// joined `package_name` string, in language `lang`'s spelling.
///
/// This is the load-side counterpart of the M1 construction bridge: a
/// declaration's `FqName` is `[package prefix] ++ [short_name tail]`, and for
/// languages whose `package_name` is derived from the FILE PATH (Go import
/// paths, Python/Rust module paths) the store recomputes `package_name`
/// per-path on load (`LanguageAdapter::hydrate_content_qualifier`) while the
/// same content blob may be shared across paths. The `short_name` tail is
/// content-stable and is what gets persisted; this function reconstructs the
/// path-dependent prefix from the live `package_name` so the loaded `FqName`
/// matches the extraction-time one for THAT path.
///
/// Re-tokenizing the already-joined `package_name` (which the extractor itself
/// built from structured components) is the sanctioned bridge, NOT the banned
/// "regex instead of tree-sitter": there is no richer AST for a
/// already-collapsed path string, the components cannot contain their own
/// separator (Go path steps have no `/`, dotted module/namespace components no
/// `.`), and the write side asserts (`starts_with`) that the reconstruction
/// reproduces the extractor's leading segments byte-for-byte. Separator/kind by
/// language, mirroring each extractor's package segmentation:
/// Go splits `/` into [`SegmentKind::Path`]; C++ splits `::` into
/// [`SegmentKind::Package`]; every other package-bearing language splits `.`
/// into [`SegmentKind::Package`]; Ruby/JavaScript/TypeScript never carry a
/// package (`package_name` is always empty) so the prefix is empty.
pub fn package_prefix_fq(lang: Language, package_name: &str, interner: &SegmentInterner) -> FqName {
    let mut fq = FqName::new();
    if package_name.is_empty() {
        return fq;
    }
    let (delimiter, kind): (&str, SegmentKind) = match lang {
        Language::Go => ("/", SegmentKind::Path),
        Language::Cpp => ("::", SegmentKind::Package),
        _ => (".", SegmentKind::Package),
    };
    for component in package_name.split(delimiter) {
        fq.push(interner.intern(component, kind));
    }
    fq
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fq(interner: &SegmentInterner, parts: &[(&str, SegmentKind)]) -> FqName {
        let mut name = FqName::new();
        for &(text, kind) in parts {
            name.push(interner.intern(text, kind));
        }
        name
    }

    #[test]
    fn intern_dedups_by_text_and_kind() {
        let interner = SegmentInterner::new();
        let a = interner.intern("foo", SegmentKind::Member);
        let b = interner.intern("foo", SegmentKind::Member);
        assert_eq!(a, b, "same text+kind must intern to the same id");

        let c = interner.intern("foo", SegmentKind::Type);
        assert_ne!(a, c, "same text, different kind must be a distinct entry");

        assert_eq!(interner.resolve(a), ("foo", SegmentKind::Member));
        assert_eq!(interner.resolve(c), ("foo", SegmentKind::Type));
    }

    #[test]
    fn display_round_trips_go_import_path() {
        // github.com/foo/bar.Baz.method — the `/`-joined path head must survive.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("github.com", SegmentKind::Path),
                ("foo", SegmentKind::Path),
                ("bar", SegmentKind::Path),
                ("Baz", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
        );
        assert_eq!(name.display(&interner), "github.com/foo/bar.Baz.method");
    }

    #[test]
    fn display_preserves_literal_dots_colons_hashes_in_segments() {
        // The whole point: a segment's text is free-form and never re-split.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("a.b", SegmentKind::Path),
                ("ns::inner", SegmentKind::Package),
                ("r#type", SegmentKind::Member),
            ],
        );
        // Path -> Package is `.`, Package -> Member is `.`; the literal `.`,
        // `::`, and `#` inside segments are untouched.
        assert_eq!(name.display(&interner), "a.b.ns::inner.r#type");
    }

    #[test]
    fn display_companion_uses_trailing_dollar_suffix() {
        // A Scala `object` segment carries a trailing `$` on its own name and
        // joins to neighbours with `.`, matching the legacy short_name spelling
        // (`format!("{raw_name}$")` then `.`-joined) rather than a JVM-style
        // `Outer$Foo` prefix separator.
        let interner = SegmentInterner::new();

        // Top-level object: `object LocalScheduler` -> `LocalScheduler$`.
        let top = fq(&interner, &[("LocalScheduler", SegmentKind::Companion)]);
        assert_eq!(top.display(&interner), "LocalScheduler$");

        // Object member: `object Foo { def bar }` -> `Foo$.bar`.
        let member = fq(
            &interner,
            &[
                ("Foo", SegmentKind::Companion),
                ("bar", SegmentKind::Member),
            ],
        );
        assert_eq!(member.display(&interner), "Foo$.bar");

        // Object nested in a class: `class Outer { object Foo }` -> `Outer.Foo$`.
        let nested = fq(
            &interner,
            &[
                ("Outer", SegmentKind::Type),
                ("Foo", SegmentKind::Companion),
            ],
        );
        assert_eq!(nested.display(&interner), "Outer.Foo$");

        // Object nested in an object: `object Outer { object Inner }` ->
        // `Outer$.Inner$`.
        let nested_objects = fq(
            &interner,
            &[
                ("Outer", SegmentKind::Companion),
                ("Inner", SegmentKind::Companion),
            ],
        );
        assert_eq!(nested_objects.display(&interner), "Outer$.Inner$");
    }

    #[test]
    fn display_native_cpp_nested_class_uses_dollar() {
        // C++ nested classes are spelled `Outer$Inner` — the outermost class is
        // a plain Type, each subsequently nested class is `Nested` (the general
        // `$`-join mechanism shared with python/php/ruby/csharp/java, not a
        // cpp-specific rule), so `Outer$Inner` round-trips identically in BOTH
        // the canonical and native renderings.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("ns", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
                ("method", SegmentKind::Member),
            ],
        );
        assert_eq!(name.display(&interner), "ns.Outer$Inner.method");
        assert_eq!(
            name.display_native(Language::Cpp, &interner),
            "ns.Outer$Inner.method"
        );
    }

    #[test]
    fn display_native_cpp_uses_double_colon_between_packages() {
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("cutlass", SegmentKind::Package),
                ("gemm", SegmentKind::Package),
                ("warp", SegmentKind::Package),
                ("OperandStorage", SegmentKind::Type),
                ("layout", SegmentKind::Member),
            ],
        );
        assert_eq!(
            name.display(&interner),
            "cutlass.gemm.warp.OperandStorage.layout"
        );
        assert_eq!(
            name.display_native(Language::Cpp, &interner),
            "cutlass::gemm::warp.OperandStorage.layout"
        );
    }

    #[test]
    fn unknown_input_segments_render_dot_joined() {
        // A user-supplied symbol path (parsed at the input edge) is a chain of
        // `Unknown` segments; it must render to the canonical `.`-joined
        // spelling the string index is keyed by, regardless of how the segments
        // were originally spelled (`::`, `/`, ...), so an input FqName can be
        // matched by rendering against the `.`-joined `definitions` index.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("a", SegmentKind::Unknown),
                ("b", SegmentKind::Unknown),
                ("C", SegmentKind::Unknown),
            ],
        );
        assert_eq!(name.display(&interner), "a.b.C");
        // Native rendering agrees (Unknown is never Package, so C++'s `::` rule
        // never fires), and appending an Unknown reference to any scope prefix
        // joins with `.`.
        assert_eq!(name.display_native(Language::Cpp, &interner), "a.b.C");
        let pkg = interner.intern("ns", SegmentKind::Package);
        assert_eq!(
            interner.separator_between(pkg, name.segments()[0], Language::Cpp),
            "."
        );
    }

    #[test]
    fn separator_between_reports_native_boundaries() {
        let interner = SegmentInterner::new();
        let p0 = interner.intern("cutlass", SegmentKind::Package);
        let p1 = interner.intern("gemm", SegmentKind::Package);
        let ty = interner.intern("Outer", SegmentKind::Type);
        let nested = interner.intern("Inner", SegmentKind::Nested);
        // Package->Package renders `::` in C++ (a non-dot boundary the
        // shrinking-scope walk must not descend), `.` canonically.
        assert_eq!(interner.separator_between(p0, p1, Language::Cpp), "::");
        assert_eq!(interner.separator_between(p0, p1, Language::Rust), ".");
        // Package->Type is `.` everywhere; a Nested segment is always `$`.
        assert_eq!(interner.separator_between(p1, ty, Language::Cpp), ".");
        assert_eq!(interner.separator_between(ty, nested, Language::Cpp), "$");
    }

    #[test]
    fn parent_last_and_starts_with() {
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("pkg", SegmentKind::Path),
                ("Type", SegmentKind::Type),
                ("member", SegmentKind::Member),
            ],
        );
        let parent = name.parent().expect("has parent");
        assert_eq!(parent.display(&interner), "pkg.Type");
        assert_eq!(parent.len(), 2);
        assert_eq!(
            name.last(),
            Some(interner.intern("member", SegmentKind::Member))
        );
        assert!(name.starts_with(&parent));
        assert!(name.starts_with(&name));

        let unrelated = fq(&interner, &[("other", SegmentKind::Path)]);
        assert!(!name.starts_with(&unrelated));

        let empty = FqName::new();
        assert!(empty.parent().is_none());
        assert!(empty.last().is_none());
        assert!(
            name.starts_with(&empty),
            "every name starts with the empty prefix"
        );
    }

    #[test]
    fn parent_chain_walks_to_root() {
        let interner = SegmentInterner::new();
        let mut name = fq(
            &interner,
            &[
                ("a", SegmentKind::Path),
                ("B", SegmentKind::Type),
                ("c", SegmentKind::Member),
            ],
        );
        let mut rendered = Vec::new();
        loop {
            rendered.push(name.display(&interner));
            match name.parent() {
                Some(parent) if !parent.is_empty() => name = parent,
                _ => break,
            }
        }
        assert_eq!(rendered, vec!["a.B.c", "a.B", "a"]);
    }

    #[test]
    fn encode_decode_round_trips_kind_and_text() {
        // Every SegmentKind, plus free-form text containing the delimiters the
        // system used to split on (`.`, `::`, `$`, `#`), must survive the cache
        // encode/decode with kind AND text intact. Decoding re-interns into the
        // same interner, so the round-tripped FqName is integer-equal to the
        // original.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("github.com", SegmentKind::Path),
                ("cutlass::gemm", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
                ("Companion", SegmentKind::Companion),
                ("r#type", SegmentKind::Member),
                ("anything", SegmentKind::Unknown),
            ],
        );
        let encoded = name.encode_segments(&interner);
        let decoded = FqName::decode_segments(&encoded, &interner).expect("decode");
        assert_eq!(decoded, name);
        // Text and kind are individually preserved, not just the joined string.
        let pairs: Vec<_> = decoded
            .segments()
            .iter()
            .map(|&id| interner.resolve(id))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("github.com", SegmentKind::Path),
                ("cutlass::gemm", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
                ("Companion", SegmentKind::Companion),
                ("r#type", SegmentKind::Member),
                ("anything", SegmentKind::Unknown),
            ]
        );
    }

    #[test]
    fn encode_decode_empty_is_empty() {
        let interner = SegmentInterner::new();
        let empty = FqName::new();
        assert!(empty.encode_segments(&interner).is_empty());
        assert!(
            FqName::decode_segments(&[], &interner)
                .expect("decode empty")
                .is_empty()
        );
    }

    #[test]
    fn decode_rejects_malformed_blobs() {
        let interner = SegmentInterner::new();
        // Unknown kind tag.
        assert!(FqName::decode_segments(&[200, 0, 0, 0, 0], &interner).is_err());
        // Truncated length prefix.
        assert!(FqName::decode_segments(&[0, 1, 2], &interner).is_err());
        // Length claims more text than is present.
        assert!(FqName::decode_segments(&[0, 4, 0, 0, 0, b'x'], &interner).is_err());
    }

    /// Memory/size measurement (M0). Builds a representative corpus from this
    /// crate's own `src/` tree — a real, deeply-nested directory layout with
    /// heavy shared prefixes — by treating each path component as a `Path`
    /// segment, the file stem as a `Type`, and two synthesized `Member`s per
    /// file. Prints the interner entry count and interned text bytes versus the
    /// summed legacy string bytes, so the memory question is answered with
    /// numbers rather than vibes.
    #[test]
    fn measure_interned_vs_legacy_bytes() {
        use std::path::Path;

        fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_rs(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        // Guards against a walk that found nothing (a moved module tree, or the
        // test running somewhere without sources); the ratio assertion below is
        // what the test actually measures. Deliberately not tuned to the crate's
        // current file count -- #1549 moved this module and broke a `> 50` bound
        // that was standing in for "the walk worked".
        assert!(
            files.len() > 10,
            "expected a real corpus, got {}",
            files.len()
        );

        let interner = SegmentInterner::new();
        let mut legacy_bytes: usize = 0;
        let mut fq_count: usize = 0;

        for file in &files {
            let rel = file.strip_prefix(&root).unwrap();
            let mut base = FqName::new();
            // Directory components -> Path segments (shared prefixes dedup).
            for comp in rel.parent().into_iter().flat_map(Path::components) {
                let text = comp.as_os_str().to_string_lossy();
                base.push(interner.intern(&text, SegmentKind::Path));
            }
            let stem = rel.file_stem().unwrap().to_string_lossy();
            let type_fq = base.with_pushed(interner.intern(&stem, SegmentKind::Type));
            for member in ["new", "run"] {
                let member_fq = type_fq
                    .clone()
                    .with_pushed(interner.intern(member, SegmentKind::Member));
                legacy_bytes += member_fq.display(&interner).len();
                fq_count += 1;
            }
            legacy_bytes += type_fq.display(&interner).len();
            fq_count += 1;
        }

        let mut interned_entries: usize = 0;
        let mut interned_text_bytes: usize = 0;
        for shard in &interner.shards {
            let shard = shard.read().unwrap();
            interned_entries += shard.entries.len();
            for (text, _) in &shard.entries {
                interned_text_bytes += text.len();
            }
        }
        // Each SegmentId occupies 4 bytes; an FqName is a SmallVec of them.
        let id_bytes = interned_entries * std::mem::size_of::<SegmentId>();

        println!(
            "[fq_name measurement] corpus: {} files, {fq_count} fq names",
            files.len()
        );
        println!("[fq_name measurement] summed legacy string bytes: {legacy_bytes}");
        println!(
            "[fq_name measurement] interner entries: {interned_entries}, unique text bytes: {interned_text_bytes} (+{id_bytes} bytes of ids)"
        );
        println!(
            "[fq_name measurement] interned/legacy text ratio: {:.3}",
            interned_text_bytes as f64 / legacy_bytes as f64
        );

        assert!(
            interned_text_bytes < legacy_bytes,
            "interned unique text ({interned_text_bytes}) should be well under summed legacy bytes ({legacy_bytes})"
        );
    }

    #[test]
    fn global_interner_is_stable() {
        let a = segment_interner().intern("pkg", SegmentKind::Path);
        let b = segment_interner().intern("pkg", SegmentKind::Path);
        assert_eq!(a, b);
    }
}
