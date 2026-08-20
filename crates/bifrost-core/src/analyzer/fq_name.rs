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
use std::borrow::Cow;
use std::sync::{OnceLock, RwLock};

use crate::analyzer::Language;
use crate::hash::HashMap;

/// The components a legacy `separator`-joined qualified-name string contributes
/// to an [`FqName`]: every non-empty run between separators.
///
/// A frontend that still carries a qualified name as a joined string spells it
/// twice — once as the string it stores in a [`crate::analyzer::CodeUnit`]'s
/// `package_name`/`short_name`, and once as the structured `FqName` it builds
/// by interning these components. `CodeUnit::with_signature_and_fq` asserts the
/// two agree (the #1189 round-trip assert), and they can disagree in exactly
/// one way: a separator run that yields no component. Well-formed source never
/// writes one, but real corpora are full of source that is not well formed —
/// `namespace winrt::{{ namespaceCpp }}` truncated at the placeholder,
/// `package com..foo;` in a parser-test fixture, `namespace MyStandard\.hidden;`
/// in a fixture that documents its own parse error. Each of those tripped the
/// assert and aborted a whole workspace build.
///
/// Pair this with [`normalize_joined`] on the string side. Splitting here and
/// re-joining there is the SAME decision about empty components made once, so
/// the two spellings agree by construction rather than by each site
/// remembering to guard (issues #2352, #2353, #2375).
pub fn joined_segments<'a>(
    joined: &'a str,
    separator: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    joined.split(separator).filter(|part| !part.is_empty())
}

/// [`joined_segments`] put back together: the joined string that renders the
/// same segments the `FqName` will hold.
///
/// Storing this instead of the raw text is what closes the divergence. The
/// common case borrows — a clean name has no empty component to drop, so this
/// allocates only for the malformed input it exists to repair.
pub fn normalize_joined<'a>(joined: &'a str, separator: &str) -> Cow<'a, str> {
    let has_empty_component = joined.starts_with(separator)
        || joined.ends_with(separator)
        || joined.contains(&format!("{separator}{separator}"));
    if !has_empty_component {
        return Cow::Borrowed(joined);
    }
    Cow::Owned(
        joined
            .split(separator)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(separator),
    )
}

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
    /// Every variant, so a derivation over segment-kind pairs stays exhaustive
    /// when a variant is added. `persist_tag`'s `match` is the compiler-checked
    /// reminder to extend this list with it.
    pub const ALL: [SegmentKind; 7] = [
        SegmentKind::Path,
        SegmentKind::Package,
        SegmentKind::Type,
        SegmentKind::Companion,
        SegmentKind::Nested,
        SegmentKind::Member,
        SegmentKind::Unknown,
    ];

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

    // These operations keep owner walks, persistence boundaries, and
    // enclosing-scope composition on interned segments.
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

    #[allow(dead_code)]
    pub fn last(&self) -> Option<SegmentId> {
        self.segments.last().copied()
    }

    #[allow(dead_code)]
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
    /// the package boundary recorded by `CodeUnit`).
    pub fn suffix_from(&self, prefix_len: usize) -> FqName {
        FqName {
            segments: SmallVec::from_slice(&self.segments[prefix_len.min(self.segments.len())..]),
        }
    }

    /// The first `prefix_len` segments, as an owned structured name.
    pub fn prefix(&self, prefix_len: usize) -> FqName {
        FqName {
            segments: SmallVec::from_slice(&self.segments[..prefix_len.min(self.segments.len())]),
        }
    }

    /// Canonical display: `.`-joined, `/` between adjacent [`SegmentKind::Path`]
    /// segments (so import-path heads such as `github.com/foo/bar` round-trip),
    /// and a trailing `$` suffix on each [`SegmentKind::Companion`] segment (so
    /// Scala object spellings such as `LocalScheduler$` and `Outer$.Inner$`
    /// round-trip). This reproduces exactly today's user-facing `fq_name()`
    /// convention, so display output does not change.
    ///
    /// Canonical rendering for language-neutral lookup and display surfaces.
    #[allow(dead_code)]
    pub fn display(&self, interner: &SegmentInterner) -> String {
        self.render(interner, None).text
    }

    /// Native display: language-specific separators (`::` between adjacent C++
    /// [`SegmentKind::Package`] segments, `$` between adjacent C++ nested-class
    /// [`SegmentKind::Type`] segments) for surfaces that render native
    /// spellings.
    pub fn display_native(&self, lang: Language, interner: &SegmentInterner) -> String {
        self.render(interner, Some(lang)).text
    }

    /// The native rendering together with the byte span each segment occupies
    /// in it, so a caller that needs several projections of one name (its
    /// package prefix, its declaration tail, its terminal identifier, its
    /// owner's identifier) reads them as slices of a single string instead of
    /// rendering the name once per projection.
    ///
    /// Every projection is a *contiguous span* of the full rendering: a
    /// prefix's rendering is the full rendering truncated at that prefix's last
    /// segment, and a suffix's rendering is the full rendering from that
    /// suffix's first segment, because [`separator`] decides each join from the
    /// two adjacent kinds alone. [`RenderedFqName`] is that fact made
    /// mechanical -- see `rendered_spans_match_per_projection_rendering`, which
    /// pins it against the projection-by-projection rendering it replaces.
    pub fn render_native(&self, lang: Language, interner: &SegmentInterner) -> RenderedFqName {
        self.render(interner, Some(lang))
    }

    fn render(&self, interner: &SegmentInterner, native: Option<Language>) -> RenderedFqName {
        let mut text = String::new();
        let mut spans: SmallVec<[(u32, u32); 8]> = SmallVec::with_capacity(self.segments.len());
        let mut prev: Option<SegmentKind> = None;
        for &id in &self.segments {
            let (segment_text, kind) = interner.resolve(id);
            if let Some(prev_kind) = prev {
                text.push_str(separator(prev_kind, kind, native));
            }
            let start = text.len();
            text.push_str(segment_text);
            // A Scala `object` segment is spelled with a trailing `$` *suffix*
            // on its own name (`LocalScheduler$`, `Outer$.Inner$`), joined to
            // neighbours with an ordinary `.`. The `$` is part of this segment,
            // not a separator, so it is emitted here rather than by `separator`.
            if kind == SegmentKind::Companion {
                text.push('$');
            }
            spans.push((start as u32, text.len() as u32));
            prev = Some(kind);
        }
        RenderedFqName { text, spans }
    }
}

/// A rendered [`FqName`] plus the byte span of each of its segments, produced
/// by [`FqName::render_native`].
pub struct RenderedFqName {
    text: String,
    /// `(start, end)` byte offsets of each segment's own text in `text`. `end`
    /// includes a [`SegmentKind::Companion`] segment's trailing `$`, which is
    /// part of that segment's spelling rather than a join.
    spans: SmallVec<[(u32, u32); 8]>,
}

impl RenderedFqName {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn into_text(self) -> String {
        self.text
    }

    /// Byte offset at which segment `index`'s own text starts.
    pub fn segment_start(&self, index: usize) -> usize {
        self.spans[index].0 as usize
    }

    /// Byte offset just past segment `index`'s own text.
    pub fn segment_end(&self, index: usize) -> usize {
        self.spans[index].1 as usize
    }

    /// End offset of `FqName::prefix(len)`'s rendering: `text[..prefix_end(len)]`
    /// is byte-identical to rendering that prefix on its own.
    pub fn prefix_end(&self, len: usize) -> usize {
        match len {
            0 => 0,
            len => self.segment_end(len.min(self.spans.len()) - 1),
        }
    }

    /// Start offset of `FqName::suffix_from(len)`'s rendering:
    /// `text[suffix_start(len)..]` is byte-identical to rendering that suffix on
    /// its own.
    pub fn suffix_start(&self, len: usize) -> usize {
        if len >= self.spans.len() {
            self.text.len()
        } else {
            self.segment_start(len)
        }
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

/// Every separator string [`separator`] can emit between two adjacent segments,
/// across all languages. The universe the per-language derivations below
/// partition.
const ALL_SEGMENT_SEPARATORS: [&str; 4] = ["/", "$", "::", "."];

/// Separators that [`separator`] can emit for *some* language but never for
/// `lang`.
///
/// This is a storage contract, not a heuristic. A `CodeUnit`'s persisted
/// `short_name` is `fq.suffix_from(package_segment_count)` rendered by
/// [`FqName::display_native`], which joins segments with nothing but
/// [`separator`]'s output. A separator this function returns therefore cannot
/// appear between two segments of any `short_name` stored for `lang`, so a
/// lookup spelling that carries one is a guaranteed miss against the
/// `(lang, short_name)` index -- it can be dropped before it costs a pooled
/// connection checkout, a generation check, a `prepare_cached` and an index
/// probe (issue #1748; `.agents/docs/graph-read-cost-investigation-2026-08.md`
/// measured 0 of 324,891 stored `short_name` values containing `::`).
///
/// Derived exhaustively over [`SegmentKind::ALL`] pairs rather than written out
/// as a second list, so a new language-specific rule in [`separator`] changes
/// this answer instead of silently disagreeing with it. C++ is the one language
/// that renders `::`, and it is excluded from nothing here for exactly that
/// reason.
///
/// The contract bounds what a *separator* can be, never what a segment's own
/// text can be. Scala's cons class is literally named `::`, so `::` and
/// `::.head` are ordinary scala short names whose `::` is a segment's text.
/// This answer alone therefore does not license dropping a spelling: the
/// caller must also know that the separator is one its own lookup vocabulary
/// treats as a join. See `LanguageAdapter::lookup_candidate_separators`, which
/// is where a language declares that -- and scala's declines `::` for exactly
/// this reason.
pub fn absent_segment_separators(lang: Language) -> &'static [&'static str] {
    static TABLE: OnceLock<HashMap<Language, Vec<&'static str>>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            let mut table = HashMap::default();
            for language in std::iter::once(Language::None).chain(Language::ANALYZABLE) {
                let emitted: Vec<&'static str> = SegmentKind::ALL
                    .iter()
                    .flat_map(|&prev| {
                        SegmentKind::ALL
                            .iter()
                            .map(move |&cur| separator(prev, cur, Some(language)))
                    })
                    .collect();
                table.insert(
                    language,
                    ALL_SEGMENT_SEPARATORS
                        .into_iter()
                        .filter(|candidate| !emitted.contains(candidate))
                        .collect(),
                );
            }
            table
        })
        .get(&lang)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Number of interner shards. Extraction is file-parallel, so `intern` spreads
/// contention across independent locks; each shard owns a disjoint slice of the
/// `SegmentId` space.
const SHARD_COUNT: usize = 16;

/// Entries in a shard's first entry chunk. Each subsequent chunk doubles, so
/// the chunk table is a small fixed array and a shard still reaches the whole
/// `SegmentId` space it owns.
const FIRST_ENTRY_CHUNK_LEN: usize = 64;

/// Chunks per shard. `FIRST_ENTRY_CHUNK_LEN * (2^24 - 1)` is a little over one
/// billion entries per shard, well past the `u32::MAX / SHARD_COUNT` ceiling
/// [`SegmentInterner::encode`] can address at all.
const ENTRY_CHUNK_COUNT: usize = 24;

/// An interned `(leaked text, kind)` pair. The text is leaked once on first
/// insert so [`SegmentInterner::resolve`] can hand back a `&str` that outlives
/// any borrow of the interner; the interner is grow-only for the process
/// lifetime, so this is bounded by the segment vocabulary.
type Entry = (&'static str, SegmentKind);

/// One shard's grow-only entry table: a fixed chunk directory whose chunks are
/// allocated on demand and never moved.
type EntryChunks = [OnceLock<Box<[OnceLock<Entry>]>>; ENTRY_CHUNK_COUNT];

/// The chunk and in-chunk offset holding a shard's `local`th entry. Chunk `c`
/// holds `FIRST_ENTRY_CHUNK_LEN << c` entries starting at
/// `FIRST_ENTRY_CHUNK_LEN * ((1 << c) - 1)`.
fn entry_slot(local: usize) -> (usize, usize) {
    let chunk = (local / FIRST_ENTRY_CHUNK_LEN + 1).ilog2() as usize;
    (chunk, local - FIRST_ENTRY_CHUNK_LEN * ((1 << chunk) - 1))
}

fn entry_chunk_len(chunk: usize) -> usize {
    FIRST_ENTRY_CHUNK_LEN << chunk
}

struct Shard {
    /// `text -> [(kind, id)]`. Keyed by owned `String` so lookups on the hot
    /// (hit) path borrow a `&str` without allocating. Guarded by the shard's
    /// `RwLock`; only [`SegmentInterner::intern`] touches it.
    by_text: HashMap<String, SmallVec<[(SegmentKind, SegmentId); 2]>>,
    /// Number of entries published in `entries`. Guarded by the same lock, so
    /// the next local index is decided by whichever writer holds it.
    len: usize,
}

/// Sharded, concurrent interner of `(text, kind)` pairs.
///
/// [`Self::resolve`] takes no lock. A `SegmentId` names a fixed slot in a
/// grow-only chunked table, and the chunk a slot lives in never moves once
/// allocated, so a read is two acquire loads and an index -- not the
/// read-modify-write pair an `RwLock` read guard costs on every acquire and
/// release. That matters because resolve runs once per segment per rendering,
/// on every thread that touches a name (issue #1928 measured 6.55% of a
/// chromium probe phase inside it).
pub struct SegmentInterner {
    shards: [RwLock<Shard>; SHARD_COUNT],
    /// Per-shard entry table. Written only under the shard's write lock; read
    /// without any lock. `OnceLock` is what makes that safe: a chunk is
    /// published whole, and a slot is published only after its entry is
    /// written, which happens-before the id naming that slot escapes the
    /// writer.
    entries: [EntryChunks; SHARD_COUNT],
}

impl SegmentInterner {
    fn new() -> Self {
        SegmentInterner {
            shards: std::array::from_fn(|_| {
                RwLock::new(Shard {
                    by_text: HashMap::default(),
                    len: 0,
                })
            }),
            entries: std::array::from_fn(|_| std::array::from_fn(|_| OnceLock::new())),
        }
    }

    fn shard_of(text: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        text.hash(&mut hasher);
        (hasher.finish() as usize) % SHARD_COUNT
    }

    fn encode(shard: usize, local: usize) -> SegmentId {
        let id = local * SHARD_COUNT + shard;
        assert!(
            id <= u32::MAX as usize,
            "segment interner exhausted its id space (shard={shard}, local={local})"
        );
        SegmentId(id as u32)
    }

    pub fn intern(&self, text: &str, kind: SegmentKind) -> SegmentId {
        #[cfg(any(test, feature = "test-support"))]
        counters::record_intern();
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
        let local = shard.len;
        let id = Self::encode(shard_idx, local);
        let leaked: &'static str = Box::leak(text.to_owned().into_boxed_str());
        let (chunk, offset) = entry_slot(local);
        let slots = self.entries[shard_idx][chunk].get_or_init(|| {
            (0..entry_chunk_len(chunk))
                .map(|_| OnceLock::new())
                .collect()
        });
        slots[offset]
            .set((leaked, kind))
            .expect("a segment entry slot is filled exactly once");
        shard.len = local + 1;
        shard
            .by_text
            .entry(text.to_owned())
            .or_default()
            .push((kind, id));
        id
    }

    pub fn resolve(&self, id: SegmentId) -> (&str, SegmentKind) {
        #[cfg(any(test, feature = "test-support"))]
        counters::record_resolve();
        let shard_idx = (id.0 as usize) % SHARD_COUNT;
        let (chunk, offset) = entry_slot((id.0 as usize) / SHARD_COUNT);
        // Both `expect`s are unreachable for an id this interner issued: the
        // chunk and the slot are filled before the id escapes `intern`. An id
        // from a *different* interner is the only way to reach them, and that
        // is a caller bug rather than a state to recover from.
        let (text, kind) = *self.entries[shard_idx][chunk]
            .get()
            .expect("SegmentId names an allocated entry chunk")[offset]
            .get()
            .expect("SegmentId names a filled entry slot");
        // `text` is `&'static str`; returning it under `&self`'s lifetime is a
        // safe subtyping shrink.
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
/// A single process-global interner avoids threading workspace-local interners
/// through every extractor. Entries are tiny, grow-only, and text-deduplicated.
pub fn segment_interner() -> &'static SegmentInterner {
    static INTERNER: OnceLock<SegmentInterner> = OnceLock::new();
    INTERNER.get_or_init(SegmentInterner::new)
}

/// Per-thread counts of interner traffic, so a test can pin how much identity
/// work a construction path does (issue #1928) without timing anything.
///
/// Thread-local rather than global: the counted work happens on the calling
/// thread, and a per-thread count stays exact whether the suite runs each test
/// in its own process or many tests as threads of one.
#[cfg(any(test, feature = "test-support"))]
pub mod counters {
    use std::cell::Cell;

    thread_local! {
        static RESOLVE_CALLS: Cell<u64> = const { Cell::new(0) };
        static INTERN_CALLS: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn record_resolve() {
        RESOLVE_CALLS.with(|calls| calls.set(calls.get() + 1));
    }

    pub(super) fn record_intern() {
        INTERN_CALLS.with(|calls| calls.set(calls.get() + 1));
    }

    /// `(resolve calls, intern calls)` made by this thread since the last
    /// [`reset`].
    pub fn counts() -> (u64, u64) {
        (RESOLVE_CALLS.with(Cell::get), INTERN_CALLS.with(Cell::get))
    }

    pub fn reset() {
        RESOLVE_CALLS.with(|calls| calls.set(0));
        INTERN_CALLS.with(|calls| calls.set(0));
    }
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

    /// The whole point of the pair: whatever `normalize_joined` stores must
    /// re-split into exactly the components `joined_segments` interns, so the
    /// `CodeUnit::with_signature_and_fq` boundary search cannot fail (#1189).
    #[test]
    fn normalize_joined_agrees_with_joined_segments() {
        for (raw, separator) in [
            // Well formed: every one of these must survive untouched.
            ("com.example.pkg", "."),
            ("cutlass::gemm::warp", "::"),
            ("", "."),
            ("single", "::"),
            // The malformed shapes that aborted real workspace builds.
            ("winrt::", "::"),           // #2353 react-native-windows
            ("com..foo", "."),           // #2375 intellij-community
            ("MyStandard..hidden", "."), // #2352 PHP_CodeSniffer
            (".ArrayObject", "."),       // #2350 phan
            ("::", "::"),
            ("...", "."),
        ] {
            let normalized = normalize_joined(raw, separator);
            let rejoined = joined_segments(&normalized, separator).collect::<Vec<_>>();
            assert_eq!(
                rejoined.join(separator),
                *normalized,
                "normalize_joined({raw:?}, {separator:?}) must be a fixed point of the split"
            );
            assert_eq!(
                joined_segments(raw, separator).collect::<Vec<_>>(),
                rejoined,
                "normalizing must not change which components the fq gets ({raw:?})"
            );
        }
    }

    /// A clean name must not allocate: this runs on every declaration.
    #[test]
    fn normalize_joined_borrows_a_clean_name() {
        assert!(matches!(
            normalize_joined("com.example.pkg", "."),
            Cow::Borrowed(_)
        ));
        assert!(matches!(normalize_joined("com..foo", "."), Cow::Owned(_)));
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
        for (shard_idx, shard) in interner.shards.iter().enumerate() {
            let len = shard.read().unwrap().len;
            interned_entries += len;
            for local in 0..len {
                let (text, _) = interner.resolve(SegmentInterner::encode(shard_idx, local));
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

    /// The contract [`RenderedFqName`] rests on: every prefix and suffix span
    /// it reports is byte-identical to rendering that prefix or suffix on its
    /// own. Checked over shapes covering every separator rule (`/` between
    /// paths, `::` between C++ packages, `$` before a nested segment, `$`
    /// suffixed onto a companion, and the default `.`), in every language whose
    /// rules can differ.
    #[test]
    fn rendered_spans_match_per_projection_rendering() {
        use SegmentKind::*;
        let interner = SegmentInterner::new();
        let shapes: [&[(&str, SegmentKind)]; 6] = [
            &[("only", Member)],
            &[
                ("github.com", Path),
                ("foo", Path),
                ("Baz", Type),
                ("m", Member),
            ],
            &[
                ("cutlass", Package),
                ("gemm", Package),
                ("Op", Type),
                ("layout", Member),
            ],
            &[
                ("ns", Package),
                ("Outer", Type),
                ("Inner", Nested),
                ("m", Member),
            ],
            &[("Outer", Companion), ("Inner", Companion), ("bar", Member)],
            &[("a", Unknown), ("b", Unknown), ("C", Unknown)],
        ];
        for shape in shapes {
            let name = fq(&interner, shape);
            for language in [Language::None, Language::Cpp, Language::Scala, Language::Go] {
                let rendered = name.render_native(language, &interner);
                assert_eq!(
                    rendered.text(),
                    name.display_native(language, &interner),
                    "{shape:?} in {language:?}"
                );
                for split in 0..=name.len() {
                    assert_eq!(
                        &rendered.text()[..rendered.prefix_end(split)],
                        name.prefix(split).display_native(language, &interner),
                        "prefix {split} of {shape:?} in {language:?}"
                    );
                    assert_eq!(
                        &rendered.text()[rendered.suffix_start(split)..],
                        name.suffix_from(split).display_native(language, &interner),
                        "suffix {split} of {shape:?} in {language:?}"
                    );
                }
                for index in 0..name.len() {
                    assert_eq!(
                        &rendered.text()
                            [rendered.segment_start(index)..rendered.segment_end(index)],
                        name.prefix(index + 1)
                            .suffix_from(index)
                            .display_native(language, &interner),
                        "segment {index} of {shape:?} in {language:?}"
                    );
                }
            }
        }
    }

    /// The chunked entry table must resolve every id across several chunk
    /// boundaries, not just the first chunk. The first three chunks hold
    /// `64 + 128 + 256` entries, so this crosses two boundaries per shard even
    /// after ids spread over 16 shards.
    #[test]
    fn resolve_crosses_entry_chunk_boundaries() {
        let interner = SegmentInterner::new();
        let ids: Vec<_> = (0..4096)
            .map(|index| interner.intern(&format!("segment_{index}"), SegmentKind::Member))
            .collect();
        for (index, &id) in ids.iter().enumerate() {
            assert_eq!(
                interner.resolve(id),
                (format!("segment_{index}").as_str(), SegmentKind::Member)
            );
        }
        // Re-interning finds the same ids, so the by_text index and the entry
        // table stayed in step across every growth step.
        for (index, &id) in ids.iter().enumerate() {
            assert_eq!(
                interner.intern(&format!("segment_{index}"), SegmentKind::Member),
                id
            );
        }
    }

    #[test]
    fn entry_slots_tile_the_local_index_space() {
        let mut expected_chunk = 0;
        let mut expected_offset = 0;
        for local in 0..100_000 {
            assert_eq!(entry_slot(local), (expected_chunk, expected_offset));
            expected_offset += 1;
            if expected_offset == entry_chunk_len(expected_chunk) {
                expected_chunk += 1;
                expected_offset = 0;
            }
        }
        assert!(
            expected_chunk < ENTRY_CHUNK_COUNT,
            "the chunk table must cover the ids the interner can issue"
        );
    }

    #[test]
    fn global_interner_is_stable() {
        let a = segment_interner().intern("pkg", SegmentKind::Path);
        let b = segment_interner().intern("pkg", SegmentKind::Path);
        assert_eq!(a, b);
    }

    /// The storage contract issue #1748's structural-miss filter rests on. `::`
    /// is renderable only between two C++ `Package` segments, so every other
    /// language's persisted `short_name` vocabulary excludes it -- and C++'s
    /// does not, which is why the filter must be derived per language rather
    /// than hardcoded.
    #[test]
    fn absent_separators_exclude_double_colon_everywhere_but_cpp() {
        for language in Language::ANALYZABLE {
            let absent = absent_segment_separators(language);
            if language == Language::Cpp {
                assert!(
                    !absent.contains(&"::"),
                    "cpp renders `::` between namespaces, so nothing may be dropped for it"
                );
            } else {
                assert!(
                    absent.contains(&"::"),
                    "{language:?} has no `::` rendering rule, so a `::`-bearing spelling \
                     cannot match one of its persisted short names"
                );
            }
        }
    }

    /// The separators the renderer *does* emit are never reported absent: `.`
    /// is the default join, `$` precedes every `Nested` segment, and `/` joins
    /// two `Path` segments, in every language.
    #[test]
    fn absent_separators_never_claim_a_renderable_separator() {
        for language in Language::ANALYZABLE {
            let absent = absent_segment_separators(language);
            for renderable in [".", "$", "/"] {
                assert!(
                    !absent.contains(&renderable),
                    "{language:?} renders {renderable:?}, so it must not be reported absent"
                );
            }
        }
    }
}
