# PHP wave diagnosis: 59 census tier-1 missing sites (bifrost head 90d65613)

Input: `/mnt/optane/tmp/bifrost-fird/php-missing-90d65613.json` (59 sites, 20 repos, probe-seed
census, tier 1). All 59 sites were read individually. No sampling.

## Headline

Every one of the 59 sites is the same syntactic shape: **a bare (unqualified) call to a
global/builtin PHP function, made from inside a namespaced class or trait**. Not one site is a
call that PHP could bind to the same-file declaration the census credits.

Two independent mechanisms produce the 59 rows:

- **M1 (grading defect, 59/59 sites).** `bare_call_reaches_same_file_declaration` returns
  unconditional `true` for PHP on the premise that PHP "reaches [the enclosing type] through
  implicit `$this`". That premise is false. PHP has no implicit-receiver method call: `foo()`
  inside a class *never* binds to `$this->foo()`; it binds to a function in the current namespace,
  a `use function` alias, or the global function. So a same-file *method* or *property* named `N`
  is not evidence that a bare `N(...)` could have bound to it. This mis-grades all 59 to tier 1.
- **M2 (real forward-resolution gap, 9/59 sites).** `resolve_php_function` qualifies an unqualified
  call with the current namespace only and never falls back to the global namespace, which PHP's
  name resolution requires. In 9 sites the workspace *does* contain the intended global function
  (`tenancy()`, `config()`, `model()`, `app()` in `helpers.php` / `Common.php`), so forward
  navigation genuinely fails on a target Bifrost has indexed. The same omission affects unqualified
  *constants*.

M2 is only visible in this census by accident: those 9 files happen to also declare a property with
the same name (`protected Tenancy $tenancy`, `protected $config`, `protected $model`,
`protected $app`), which is what promoted them to tier 1. Fixing M1 alone would silence the one
real PHP defect in the census.

## Family table

| Family | Mechanism | Sites | Same-file "evidence" the census credited | Forward answer today | Judge |
| --- | --- | --- | --- | --- | --- |
| **F-A: builtin shadowed by a same-name method** | M1 | 40 | a method/static method of a class or trait in the file (`Monolog\Utils::substr`, `CarbonInterval::round/abs`, `Rounding::floor`, `Filesystem::copy/rmdir`, `SocketHandler::fwrite/fsockopen/pfsockopen`, `Helper::substr`, `File::realpath`, `Cosine::acos`, `RedisEngine::unserialize`, `ViewBlock::end`, `Countable::count` impls) | `no_definition` + `no_indexed_definition` — **correct** (PHP runtime function, not in workspace) | census-grading fix |
| **F-B: builtin colliding with a same-name property** | M1 | 5 | a property/promoted ctor param (`private $time`, `private $hash`, `private ?int $max`) | `no_definition` — **correct** | census-grading fix |
| **F-C: workspace-defined global helper** | M1 + **M2** | 9 | a property (`$tenancy` x4, `$config` x3, `$model`, `$app`) | `no_definition`, FQN wrongly namespace-qualified — **wrong**; the definition is indexed | **straightforward generalized fix** (resolver) + census-grading fix |
| **F-D: external-package global helper** | M1 | 5 | property x4 (`$config` x3, `$app`) / method x1 (`TestResponse::dump`) | `no_definition` — correct (no `vendor/` in the clones; laravel `config()`/`app()`, symfony `dump()`) | census-grading fix |

Totals: 59 = 40 + 5 + 9 + 5. By repo:

| Repo | F-A/F-B (builtin) | F-C (real gap) | F-D (external) |
| --- | --- | --- | --- |
| briannesbitt__Carbon | 15 | 0 | 0 |
| Seldaek__monolog | 12 | 0 | 0 |
| composer__composer | 6 | 0 | 0 |
| codeigniter4__CodeIgniter4 | 1 | 4 (`config` x3, `model`) | 0 |
| archtechx__tenancy | 0 | 4 (`tenancy` x4) | 4 (`config` x3, `app`) |
| laravel__framework | 3 | 1 (`app`) | 1 (`dump`) |
| cakephp__cakephp | 2 | 0 | 0 |
| symfony__console | 2 | 0 | 0 |
| phpactor__phpactor | 2 | 0 | 0 |
| PHPOffice__PhpSpreadsheet | 2 | 0 | 0 |

Distinct names: `substr` 8, `round` 6, `abs` 6, `config` 6, `count` 5, `tenancy` 4, `time` 3,
`app` 2, `floor` 2, `copy` 2, and 13 singletons (`sleep`, `dump`, `explode`, `unserialize`, `end`,
`serialize`, `hash`, `rmdir`, `model`, `max`, `pfsockopen`, `fsockopen`, `fwrite`, `acos`,
`realpath`). 45 of the 59 names are PHP runtime builtins.

## Falsified premises

1. **"Carbon is macro/magic-method heavy (`__call`, `@method` docblocks); its 15 sites may be PHP's
   #1803 analogue."** Falsified. All 15 Carbon sites are bare `round`/`abs`/`floor`/`serialize`
   builtin calls (`src/Carbon/CarbonInterval.php` x13, `src/Carbon/Traits/Rounding.php` x2,
   `src/Carbon/Traits/Serialization.php` x1). No `__call`, no docblock-only declaration, no macro is
   involved in any of them. The same-file names are ordinary `public function round(...)` etc.
2. **"monolog/laravel: check trait members, first-class callable syntax `foo(...)`, enum cases,
   match arms."** Falsified. monolog's 12 = `Utils::substr` shadowing (7), `$time` property
   collisions (2), and `SocketHandler`'s deliberate `protected function fwrite/fsockopen/pfsockopen`
   test seams (3). No first-class callable, enum case, or match arm appears at any of the 59 sites.
   Traits appear only as the *container* of an ordinary bare builtin call (Carbon `Rounding`), which
   is family F-A, not a trait-resolution problem.
3. **"Declarations that exist only via docblocks/magic, correctly unindexable => census-grading
   question."** Half-right for the wrong reason: it *is* a census-grading question, but no
   declaration is missing anywhere. Every credited declaration is indexed; it is simply not
   reachable from a bare call.
4. **"PHP's arm of `bare_call_reaches_same_file_declaration` may be unconditional like Scala's
   was."** **Confirmed** (`src/reference_differential/mod.rs:1435`). This is the only prior that held.
5. **Hypothesis raised and killed during the investigation: "the `if (! function_exists('x')) { ... }`
   guard around Laravel/CI4/tenancy helpers hides the declaration from extraction."** Falsified by
   fixture `f2_global_helper` and by `search_symbols` on the real clone: `src/helpers.php:11` is
   indexed as the global symbol `tenancy`, and the guarded fixture function resolves from a
   global-namespace caller and through `use function`. `crates/bifrost-php/src/declarations.rs:131-136`
   descends into any non-class container node, so `if`-guarded top-level functions are indexed.

## Reproduction

Exact single-site reruns (`run-repo --probe-seed census --tiers 1 --cache-mode ephemeral --path ...
--start-byte ... --end-byte ...`, outputs in `/mnt/optane/tmp/bifrost-fird/php-reruns/`) reproduce
9/9 spot-checked sites byte-identically, one per family and per major repo:

| site | repo / path:line | text | forward_status | tier |
| --- | --- | --- | --- | --- |
| 0 | laravel `.../Factories/Factory.php:1159` | count | no_definition (`Illuminate.Database.Eloquent.Factories.count`) | 1 |
| 1 | laravel `.../Support/ServiceProvider.php:589` | app | no_definition (`Illuminate.Support.app`) | 1 |
| 7 | Carbon `src/Carbon/CarbonInterval.php:1010` | round | no_definition (`Carbon.round`) | 1 |
| 29 | CodeIgniter4 `system/Filters/Filters.php:378` | config | no_definition (`CodeIgniter.Filters.config`) | 1 |
| 32 | CodeIgniter4 `system/RESTful/BaseResource.php:70` | model | no_definition (`CodeIgniter.RESTful.model`) | 1 |
| 39 | tenancy `src/Middleware/InitializeTenancyByDomain.php:27` | tenancy | no_definition (`Stancl.Tenancy.Middleware.tenancy`) | 1 |
| 43 | monolog `.../Handler/DeduplicationHandler.php:114` | time | no_definition (`Monolog.Handler.time`) | 1 |
| 48 | monolog `src/Monolog/Utils.php:27` | substr | no_definition (`Monolog.substr`) | 1 |
| 57 | PhpSpreadsheet `.../Trig/Cosine.php:88` | acos | no_definition (`PhpOffice...Trig.acos`) | 1 |

Product-surface confirmation of F-C (not just the differential harness):

```
bifrost --root /mnt/T9/repo-clones/archtechx__tenancy --tool get_definitions_by_location \
  --sources src --args '{"references":[{"path":"src/Middleware/InitializeTenancyByDomain.php","line":27,"column":36}]}'
-> status "no_definition": "`tenancy` resolved to `Stancl.Tenancy.Middleware.tenancy`,
   but no indexed PHP definition was found"
```

while `search_symbols --patterns '["tenancy"]'` on the same workspace reports
`{"line":11,"signature":"function tenancy() { ... }","symbol":"tenancy","path":"src/helpers.php"}`.
The target is indexed; navigation to it fails.

## Fixtures and perturbation matrices

Under `/mnt/optane/tmp/bifrost-fird/php-fixtures/` (each a git repo; run with
`run-repo --language php --probe-seed census --tiers 1,2,3 --cache-mode ephemeral`; results in the
sibling `<name>.jsonl`).

### `f1_builtin_shadow/Utils.php` — families F-A and F-B, minimal

`namespace Demo\Support; class Utils` with `public static function substr(...)`, a
`private $time` property, and one call per row.

| line | call form | forward_status / FQN | tier | classification |
| --- | --- | --- | --- | --- |
| 12 | bare `substr(...)` inside the same-named method | no_definition `Demo.Support.substr` | 1 | **missing** (mis-graded) |
| 17 | bare `strlen(...)`, no same-file name | no_definition `Demo.Support.strlen` | 3 | inconclusive (correct) |
| 22 | bare `substr(...)` in an unrelated method | no_definition `Demo.Support.substr` | 1 | **missing** (mis-graded) |
| 27 | `\substr(...)` | unresolvable_import_boundary → `substr` | - | inconclusive |
| 32 | `$this->substr(...)` | resolved `Demo.Support.Utils.substr` | - | editor_only |
| 37 | `self::substr(...)` | resolved `Demo.Support.Utils.substr` | - | editor_only |
| 42 | bare `time()` with a same-file `private $time` | no_definition `Demo.Support.time` | 1 | **missing** (mis-graded, property evidence) |

Rows 12/22 vs 17 isolate M1 exactly: identical semantics, opposite tiers, decided purely by whether
an unreachable same-file name happens to collide. Row 42 shows the evidence need not even be
callable. Rows 27/32/37 are the reachable forms and all behave correctly.

### `f2_global_helper/` — family F-C, minimal

`helpers.php` (global namespace) declares `plain_helper()` and, inside
`if (! function_exists('guarded_helper'))`, `guarded_helper()`. `namespaced_helpers.php` declares
`Demo\App\same_namespace_helper()`.

| caller | call form | result |
| --- | --- | --- |
| `Caller.php:11` (`namespace Demo\App`) | bare `plain_helper('a')` | **no_definition** `Demo.App.plain_helper` |
| `Caller.php:16` | bare `guarded_helper('a')` | **no_definition** `Demo.App.guarded_helper` |
| `Caller.php:21` | `\plain_helper('a')` | resolved `plain_helper`, consistent |
| `Caller.php:26` | `\guarded_helper('a')` | resolved `guarded_helper`, consistent |
| `Caller.php:31` | `use function guarded_helper as aliased_helper;` then `aliased_helper('a')` | resolved `guarded_helper`, consistent |
| `Caller.php:36` | bare `same_namespace_helper('a')` | resolved `Demo.App.same_namespace_helper`, consistent |
| `GlobalCaller.php:7,12` | bare calls from the global namespace | resolved, consistent |

The matrix pins M2 to exactly one cell: *unqualified name + namespaced caller + global definition*.
Every other combination already works, including the `function_exists` guard, which falsifies the
extraction hypothesis.

### `f3_same_file_function/Mixed.php` — the positive control a grading fix must not break

`namespace Demo\Mixed;` with a free `function local_helper()`, a `trait Roundable { function floor() }`,
and `class Mixed { use Roundable; }`.

| line | call form | result |
| --- | --- | --- |
| 24 | bare `local_helper('a')` (same file, same namespace, free function) | **resolved**, consistent |
| 14 | bare `floor($value)` inside the trait that declares `floor` | no_definition, tier 1, **missing** (mis-graded) |
| 29 | bare `floor($v)` in the class that `use`s the trait | no_definition, tier 1, **missing** (mis-graded) |
| 34 | `$this->floor($v)` | resolved `Demo.Mixed.Mixed.floor`, editor_only |

Line 24 is the case a PHP census predicate must keep answering `true`: a same-file *free function*
in the file's namespace really is reachable from a bare call. Lines 14/29 are what it must reject.

### `f4_global_constant/` — M2 generalizes to constants

| line | form | result |
| --- | --- | --- |
| `Reader.php:9` | bare `DEMO_LIMIT` from `namespace Demo\App` | unresolvable_import_boundary → `Demo.App._module_.DEMO_LIMIT` |
| `Reader.php:14` | `\DEMO_LIMIT` | resolved, consistent |

No census site exercises this, but the resolver defect is identical and sits in the same file.
(The outcome differs from the function case only because `Demo.App._module_` is not a workspace
package, so `php_crosses_unindexed_boundary` reports a boundary instead of `no_indexed_definition`.)

## Code citations

M1, census grading:

- `src/reference_differential/mod.rs:1406` `bare_call_reaches_same_file_declaration`.
- `src/reference_differential/mod.rs:1429-1435` — the false premise, verbatim: *"Ruby and PHP reach
  it through implicit `self`/`$this`"*, with `Language::Ruby | Language::Php => true`. Correct for
  Ruby; PHP has no implicit-receiver call syntax.
- `src/reference_differential/mod.rs:1499-1503` — `same_file_names` collapses every declaration to
  its bare identifier, discarding kind and owner, so a property (`protected Tenancy $tenancy`) and a
  method (`Utils::substr`) are indistinguishable from a free function at grading time.
- `src/reference_differential/mod.rs:1515-1524` — where that name-set answer becomes tier 1.
- `src/reference_differential/mod.rs:1392-1401` (`census_site_role`) correctly reports `BareCall`
  here; the role classification is not at fault.

M2, forward resolution:

- `crates/bifrost-php/src/aliases.rs:589-597` `resolve_php_function` — after the `\`-prefix and
  `use function` alias cases, it unconditionally returns `join_namespace(&ctx.namespace, &normalized)`.
  There is no second candidate for the global namespace.
- `crates/bifrost-php/src/aliases.rs:600-610` `resolve_php_constant` — same shape, same omission.
- `crates/bifrost-php/src/aliases.rs:401-433` `resolve_php_structured_path` (used by the bounded /
  session path via `resolve_php_function_node:305` and `resolve_php_constant_node:323`) — line 432
  has the same unconditional namespace join. Note this helper is shared with *type* resolution, where
  PHP has no global fallback, so a fix belongs on the function/constant entry points and must apply
  only to single-segment names.
- `crates/bifrost-analysis/src/analyzer/usages/get_definition/php.rs:389-397` — the function
  reference site; the single `Option<String>` it gets is handed straight to `php_fqn_outcome`.
- `crates/bifrost-analysis/src/analyzer/usages/get_definition/php.rs:858-884` `php_fqn_outcome` —
  one FQN in, candidates or a boundary/no-definition diagnostic out. This is where a
  "try the namespaced name, then the global name" retry would live.
- `crates/bifrost-analysis/src/analyzer/usages/get_definition/php.rs:1215-1233`
  `php_crosses_unindexed_boundary` — decides `unresolvable_import_boundary` vs
  `no_indexed_definition` by whether the FQN's *namespace prefix* is a workspace package. For a
  global-namespace name the prefix is `""`, so the answer flips with whether the repo happens to
  declare any global-namespace symbol (compare `f1` line 27 -> boundary, `f2` `function_exists`
  -> no_indexed_definition).
- **The same fallback rule is already modelled one layer over**:
  `crates/bifrost-php/src/diagnostics.rs:321-328` — *"PHP falls back to the global namespace for an
  unqualified function or constant. Bifrost does not index the whole built-in global surface, so this
  lookup is unfinished, not absent."* The semantic-diagnostic collector knows the rule; the
  definition resolver does not. Also `crates/bifrost-php/src/diagnostics.rs:1084-1108`
  `is_builtin_php_function` (a 21-name list that covers `count`, `substr`, `strlen` but none of
  `round`, `abs`, `floor`, `copy`, `time`, `realpath`, ...).
- Inverse side that must move with any forward change:
  `crates/bifrost-php/src/graph/inverted.rs:171-179` (call-site indexing for free functions) and
  `:427` (assignment receiver type), plus `crates/bifrost-php/src/graph/extractor.rs:601`. Fixing
  the forward direction alone would convert these 9 sites from "census gap" into genuine
  forward/inverse asymmetries.

Falsified-hypothesis citation:

- `crates/bifrost-php/src/declarations.rs:121` (`"function_definition" => self.visit_function`) and
  `:131-141` — the catch-all descends into any container node while not inside a class, so
  `if (! function_exists(...)) { function f() {} }` is indexed normally.

## Recommendations

Two separable changes; both are ordinary generalized fixes, neither needs escalation.

1. **Census grading (fixes the classification of all 59; highest priority).** Give PHP its own arm
   in `bare_call_reaches_same_file_declaration` instead of sharing Ruby's. The PHP-correct predicate
   is: *a same-file declaration is reachable from a bare call only if it is a free function
   declaration* (a function CodeUnit with no owning class), i.e. what `f3` line 24 exercises. A
   method, static method, property, promoted constructor parameter, constant, or class must answer
   `false`. This needs the declaration kind, which `same_file_names`
   (`mod.rs:1499`) currently discards; the smallest honest shape is to pass the file's
   declaration CodeUnits (not just their identifiers) into the per-language arm, exactly as the
   JS/TS arm already receives a binding index. Effect: 59 -> 0 tier-1 rows for PHP; the true
   positive in `f3` stays tier 1 if it ever regresses. Also correct the comment at `mod.rs:1429`,
   which currently states a false fact about PHP.
   *Caveat worth stating in the change*: this fix alone hides the 9 real F-C sites, so land it with
   or after fix 2, not before.

2. **Global-namespace fallback for unqualified functions and constants (fixes 9 sites, and a real
   product defect on every Laravel/CodeIgniter/tenancy-style helper call).** Model PHP's rule: for a
   single-segment, non-aliased function or constant name in a namespaced file, the candidate set is
   `[<namespace>\name, \name]`, preferring the namespaced definition when one is indexed. Apply it in
   `resolve_php_function` / `resolve_php_constant` and their structured-path twins (only on the
   function/constant entry points, never for types), and symmetrically in
   `graph/inverted.rs` and `graph/extractor.rs` so the inverse index records the same target.
   This is the change that makes "go to definition on `tenancy()` / `config()` / `model()` / `app()`"
   work at all. It is also the precondition for the residual builtin families to report a *useful*
   diagnostic: once `substr` falls back to the global name, `php_fqn_outcome` can say
   "unqualified global function, outside the indexed workspace" instead of inventing
   `Monolog.substr`, matching what `diagnostics.rs:321-328` already tells users.

3. **Optional, lower value (diagnostic quality only, 45 builtin + 5 external sites).** After fix 2,
   the boundary-vs-no-definition answer for a global name still depends on whether the repo declares
   any global-namespace symbol (`php_crosses_unindexed_boundary` with an empty namespace prefix).
   Treating an unindexed *unqualified* global function/constant as an external boundary
   unconditionally would make the diagnostic stable across repos. Not required to clear the census.

No issues were filed and no code was changed as part of this diagnosis.

## Artifacts

- Site inventory and per-site evidence script output: `/mnt/optane/tmp/bifrost-fird/php-diagnosis-report.md` (this file).
- Fixtures: `/mnt/optane/tmp/bifrost-fird/php-fixtures/{f1_builtin_shadow,f2_global_helper,f3_same_file_function,f4_global_constant}/`
  with their run outputs `f*.jsonl` alongside.
- Exact single-site reruns: `/mnt/optane/tmp/bifrost-fird/php-reruns/site-{0,1,7,29,32,39,43,48,57}.jsonl`.
  (`php-reruns/tenancy-39.jsonl` is a failed first attempt with guessed byte offsets; ignore it.)
