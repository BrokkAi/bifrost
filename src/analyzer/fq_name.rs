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
pub(crate) enum SegmentKind {
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
}

/// Interned `(text, kind)` pair. Process-local; never persisted.
///
/// The `u32` encodes both the owning interner shard and the entry index within
/// that shard (`index * SHARD_COUNT + shard`), so a bare `SegmentId` can be
/// resolved without a side table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct SegmentId(u32);

/// The qualified name. Ordered root-to-leaf. Comparisons are integer memcmp.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub(crate) struct FqName {
    segments: SmallVec<[SegmentId; 8]>,
}

impl FqName {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    // `len`, `parent`, `last`, `starts_with`, `segments`, and `display_native`
    // are the consumer-facing surface the M2 milestone wires into the shared
    // resolvers (owner-chain walking, enclosing-scope composition, the anchor
    // splitter). They exist and are unit-tested now so the API is settled, but
    // no production caller reads them until M2; the allow keeps the M1 tree
    // green under `-D warnings` without a blanket module allow.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.segments.len()
    }

    pub(crate) fn push(&mut self, id: SegmentId) {
        self.segments.push(id);
    }

    /// Builder-style push, convenient when threading a parent's name into a
    /// child at a `CodeUnit` construction site.
    pub(crate) fn with_pushed(mut self, id: SegmentId) -> Self {
        self.segments.push(id);
        self
    }

    /// The name with its final segment removed, or `None` if empty. Allocates
    /// only the SmallVec copy, never a string.
    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub(crate) fn parent(&self) -> Option<FqName> {
        if self.segments.is_empty() {
            return None;
        }
        Some(FqName {
            segments: SmallVec::from_slice(&self.segments[..self.segments.len() - 1]),
        })
    }

    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub(crate) fn last(&self) -> Option<SegmentId> {
        self.segments.last().copied()
    }

    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub(crate) fn starts_with(&self, prefix: &FqName) -> bool {
        self.segments.starts_with(&prefix.segments)
    }

    #[allow(dead_code)] // consumed in M2 (see note on `len`)
    pub(crate) fn segments(&self) -> &[SegmentId] {
        &self.segments
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
    pub(crate) fn display(&self, interner: &SegmentInterner) -> String {
        self.render(interner, None)
    }

    /// Native display: language-specific separators (`::` between adjacent C++
    /// [`SegmentKind::Package`] segments, `$` between adjacent C++ nested-class
    /// [`SegmentKind::Type`] segments) for surfaces that render native
    /// spellings — including the M1 equivalence check in
    /// [`crate::analyzer::CodeUnit::with_signature_and_fq`].
    pub(crate) fn display_native(&self, lang: Language, interner: &SegmentInterner) -> String {
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
        // C++'s legacy string spelling is mixed-separator: `::` between
        // namespace (Package) components and `$` between nested-class (Type)
        // components, joined to the terminal member with `.` (issue #1163). The
        // canonical `.`-join renders the same structure without the native
        // punctuation; both round-trip because the equivalence check renders
        // each unit natively (see `CodeUnit::with_signature_and_fq`).
        if prev == SegmentKind::Package && cur == SegmentKind::Package {
            return "::";
        }
        if prev == SegmentKind::Type && cur == SegmentKind::Type {
            return "$";
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
pub(crate) struct SegmentInterner {
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

    pub(crate) fn intern(&self, text: &str, kind: SegmentKind) -> SegmentId {
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

    pub(crate) fn resolve(&self, id: SegmentId) -> (&str, SegmentKind) {
        let shard_idx = (id.0 as usize) % SHARD_COUNT;
        let local = (id.0 as usize) / SHARD_COUNT;
        let shard = self.shards[shard_idx].read().unwrap();
        let (text, kind) = shard.entries[local];
        // `text` is `&'static str`; returning it under `&self`'s lifetime is a
        // safe subtyping shrink, and it outlives the dropped read guard.
        (text, kind)
    }
}

/// The process-global interner.
///
/// Decided in M0: a single process-global interner rather than one per
/// workspace. Threading a per-workspace interner through every `CodeUnit`
/// constructor across eleven languages is a large mechanical cost with no
/// correctness benefit while the legacy strings remain authoritative; entries
/// are tiny and text-deduplicated, and the plan explicitly permits this.
pub(crate) fn segment_interner() -> &'static SegmentInterner {
    static INTERNER: OnceLock<SegmentInterner> = OnceLock::new();
    INTERNER.get_or_init(SegmentInterner::new)
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
        // C++ nested classes are spelled `Outer$Inner` (Type$Type) natively but
        // `Outer.Inner` canonically; both must round-trip.
        let interner = SegmentInterner::new();
        let name = fq(
            &interner,
            &[
                ("ns", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("Inner", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
        );
        assert_eq!(name.display(&interner), "ns.Outer.Inner.method");
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
        assert!(
            files.len() > 50,
            "expected a large corpus, got {}",
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
