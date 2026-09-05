# PHP runtime semantic packs

This directory pins the source inputs used to build Bifrost's published PHP
builtin declaration pack. Generated manifests and shards are release assets;
they are not checked into Git.

The pinned-spec schema is ecosystem neutral and is documented in
`semantic-packs/jvm/README.md`. This directory adds the first
`php_declaration_stub` specification: an exact source set of plain `.php`
declaration stubs taken from one pinned `phpstorm-stubs` revision.

## What the pack is for

PHP programs constantly name classes and functions that no file in the
repository declares: `\PDO`, `\Redis`, the Intl classes, the reflection
classes, and unqualified builtins such as `substr` and `round`. Without this
pack, Bifrost can only report those references as leaving the workspace, with
no target. With it active, they resolve to a published declaration.

## The pinned slice

`phpstorm-stubs-2026.8.29.json` pins `phpstorm-stubs` revision
`748ab87d16253a5b5d648b5fe4dae1ff4152bb03` and lists 65 stub files, about 2.1
MB of PHP source, from twelve extension directories:

| Extension | Pinned stub files |
| --- | --- |
| `Core` | `Core/Core.php`, `Core/Core_c.php`, `Core/Core_d.php` |
| `standard` | `standard/_standard_manual.php`, `standard/basic.php`, `standard/password.php`, `standard/standard_0.php` through `standard/standard_10.php`, `standard/standard_defines.php`, `standard/streams.php` |
| `SPL` | `SPL/SPL.php`, `SPL/SPL_c1.php`, `SPL/SPL_f.php` |
| `PDO` | `PDO/PDO.php` |
| `date` | `date/date.php`, `date/date_c.php`, `date/date_d.php` |
| `json` | `json/json.php` |
| `mbstring` | `mbstring/mbstring.php` |
| `pcre` | `pcre/pcre.php` |
| `ctype` | `ctype/ctype.php` |
| `Reflection` | the 26 `Reflection/*.php` class stubs |
| `intl` | `intl/intl.php`, `intl/IntlChar.php`, `intl/IntlDatePatternGenerator.php`, `intl/IntlListFormatter.php`, `intl/IntlNumberRangeFormatter.php` |
| `redis` | `redis/Redis.php`, `redis/RedisArray.php`, `redis/RedisCluster.php`, `redis/RedisSentinel.php` |

The slice is deliberately bounded to the surfaces a PHP workspace can never
index for itself and that the PHP reference census actually names.
`phpstorm-stubs` at this revision carries roughly 180 extension directories;
pinning all of them would multiply the pack size and the extraction surface
without moving the reference families this pack exists to answer.

The pack is one slice of the PHP runtime, not the PHP runtime. It publishes
nothing about the extensions it does not list. A consumer must not read a
name's absence from this pack as a statement about PHP.

`redis` is a PECL extension rather than a bundled one; it is pinned because the
census names `\Redis` explicitly. `Relay`, which the census names beside it,
has no stub directory at this revision, so this pack says nothing about it.

Two files inside the listed directories are deliberately excluded, because
they are PhpStorm's own fictions rather than PHP surface:

- `standard/_types.php` declares `PS_UNRESERVE_PREFIX_array` and a
  `___PHPSTORM_HELPERS` namespace.
- `Reflection/.phpstorm.meta.php` declares a `PHPSTORM_META` namespace.

## Identity

A global-namespace class, interface, trait, or enum publishes under its bare
name: `PDO`, `Redis`, `ReflectionClass`, `IntlDateFormatter`. A namespaced one
publishes dot-joined, which is Bifrost's canonical PHP qualified form:
`Pdo.Sqlite`. A global function or constant publishes as a member of the
synthetic global-namespace scaffold `_php_global_`, so `substr` is the member
`substr` whose qualified name is `_php_global_.substr`. That is the same
scaffold a Composer package's `files`-autoloaded global helpers take, so one
owner-scoped query answers for both.

Declaration identities carry the `php` ecosystem term rather than the
`composer` one. The PHP runtime is not a Composer package, and a builtin class
must stay a distinct identity from a vendor class that happens to share its
name.

## What this pack does not model

The stub dialect states things a plain PHP declaration walk cannot express.
Each one is recorded as an individually named reject in the bundle's
`rejects.json` rather than silently dropped, and the pack's manifest therefore
records `completeness: partial`. At the pinned revision there are 852 rejects,
all warnings:

| Reject code | Count | Meaning |
| --- | --- | --- |
| `php.stub.language_level_type` | 584 | The declaration's type is written with `#[LanguageLevelTypeAware([...], default: ...)]`, so it depends on the runtime version. The pack publishes the natively written type and reports the declaration as read incompletely. |
| `php.stub.element_availability` | 195 | The declaration or one of its parameters carries `#[PhpStormStubsElementAvailable(...)]`, a version window this producer does not evaluate. The declaration is published unguarded. |
| `php.stub.version_variant_parameter` | 71 | The callable spells one parameter name twice, once per version window. PHP itself rejects a repeated parameter name, so the pack keeps the first spelling and reports the rest. |
| `php.stub.reserved_prefix` | 2 | The stub names a PHP reserved construct through the `PS_UNRESERVE_PREFIX_` encoding. No PHP program can call that name, so the declaration is dropped rather than published. |

A fifth code, `php.stub.docblock_only_member`, fires for a class whose docblock
declares `@method` or `@property` members. Bifrost synthesizes no declaration
from those tags, so such a class's published surface is not all of its runtime
surface. No class in the pinned slice triggers it.

The honesty rule runs one way only. Everything this producer cannot read
completely is kept and marked as read incompletely, never dropped silently and
never allowed to license an absence proof. The one exception is the
reserved-prefix case, where the *name itself* is fictional: publishing it would
put a callable in the pack that no reference can ever reach.

The attribute names above are resolved through each stub file's own `use`
bindings, because the tree imports the same attribute plainly in one file and
under an alias in another (`use ...\PhpStormStubsElementAvailable as
ElementAvailable`). Matching the written spelling would see one and miss the
other.

## Activation

The pack's compatibility and activation name the `php` toolchain over
`>=8.0.0, <9.0.0`. A workspace publishes matching evidence when it declares its
PHP version, which Bifrost reads from, in order:

1. `.php-version`, a plain `MAJOR.MINOR[.PATCH]` line (the phpenv/asdf
   convention);
2. `composer.json`'s `config.platform.php`, Composer's own exact platform pin;
3. the provable inclusive lower bound of `composer.json`'s `require.php`
   constraint, so `^8.2` pins `8.2.0` and `^7.4 || ^8.0` pins `7.4.0`.

A declaration that cannot be read exactly is an attributable refusal rather
than a guessed pin: guessing would let the pack prove a name absent for an
interpreter the workspace actually supports.

## License

`phpstorm-stubs` is licensed under the Apache License, Version 2.0. The pinned
revision and the license are recorded in the specification's provenance and in
`notices/phpstorm-stubs-2026.8.29.txt`, which ships with the pack.

## Regeneration

`scripts/public/build-pinned-php-semantic-packs.sh OUTPUT_DIR WORK_DIR [CACHE_ROOT]`
downloads the pinned archive, checks its SHA-256, copies the stub root to the
pinned directory name, and then generates and verifies the bundle. The pinned
artifact is a source set rather than one file, so its digest is the canonical
digest over the listed stub paths and bytes. Generation verifies that digest
itself and refuses a tree that differs.

When `CACHE_ROOT` is present, the recipe also installs the verified bundle into
the catalog version derived from Bifrost's current catalog schema.

GitHub builds a source archive on demand. The archive digest that the script
checks is therefore a weaker pin than the artifact digest that `generate`
enforces: a change in GitHub's archive encoding would fail the script's
checksum without any change to the pack the specification names. Repin the
archive digest in that case; the pack digest and the pinned revision stay the
same.

To run the same steps by hand:

```console
cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  /path/to/output \
  semantic-packs/php/phpstorm-stubs-2026.8.29.json /path/to/phpstorm-stubs-748ab87d1625

cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  /path/to/output
```

At the pinned revision the generated pack holds 4,994 records in one shard,
437,856 stored bytes over 3,397,237 raw bytes, from a 2,110,329-byte pinned
source set.
