# Give the Bifrost docs a semantic terrain and product-specific frame

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, the Bifrost documentation landing page should immediately communicate “code intelligence for AI” through a distinctive technical landscape made of code-analysis paths, graph nodes, and query signals. Documentation pages should share the same visual identity through a compact floating header, restrained navigation panels, and clearer active states, while remaining calm and readable. A reviewer can see the result by starting the Astro development server, opening the home page and `/capabilities/`, and resizing each page from a desktop viewport to a narrow mobile viewport.

## Progress

- [x] (2026-07-20 11:34Z) Inspected the clean detached worktree, fetched `origin`, and verified that `HEAD` exactly matches `origin/master` at `2a7d668c`.
- [x] (2026-07-20 11:34Z) Mapped the Starlight page, hero, header, sidebar, and table-of-contents extension points and confirmed that the docs dependencies are already installed.
- [x] (2026-07-20 11:49Z) Implemented the reusable semantic-terrain hero and updated the landing-page product message and capability deck.
- [x] (2026-07-20 11:49Z) Implemented the branded floating header, inset sidebar, narrow selected-link rail, and framed table of contents.
- [x] (2026-07-20 11:49Z) Ran `git diff --check`, Astro diagnostics, the production build, Pagefind indexing, and internal-link validation successfully.
- [x] (2026-07-20 11:49Z) Rendered and inspected the landing and capabilities pages at desktop and 390-pixel mobile viewports, corrected the mobile hero and mobile search/menu collision, and verified zero horizontal overflow.
- [x] (2026-07-20 11:49Z) Started the local development server at `http://127.0.0.1:4321/`, confirmed an HTTP 200 response, and left the landing page open for user review.
- [x] (2026-07-20 11:54Z) Applied browser-review feedback by removing the capability-card pictograms and ordering the header navigation to match the sidebar: Overview, Capabilities, MCP, LSP, then Querying.
- [x] (2026-07-20 12:00Z) Applied the second browser-review pass: expanded the wordmark to “Bifrost Documentation,” removed em dashes from landing copy, enlarged proof-strip typography, and converted the capability deck into four full-surface documentation links with larger titles and tighter vertical spacing.
- [x] (2026-07-20 12:05Z) Removed the medium-width headline collision while preserving the layered composition by narrowing the floating query console from 39% to 34% of the hero.
- [x] (2026-07-20 12:09Z) Linked the “Brokk” hero byline to `https://brokk.ai` with an understated, keyboard-visible link treatment.
- [x] (2026-07-20 12:15Z) Replaced the illustrative pseudo-query and fabricated latency with valid RQL, an explicit RQL marker, and result labels matching the structural call-query domain.
- [x] (2026-07-20 14:17Z) Rebased onto current `origin/master`, then re-ran Astro diagnostics and the production build; 55 pages, Pagefind indexing, and 5,007 internal links passed.

## Surprises & Discoveries

- Observation: The current landing-page animation is embedded as a large SVG string in the `hero.image.html` frontmatter field of `docs/src/content/docs/index.mdx`.
  Evidence: Starlight passes this string directly to its stock `Hero.astro`, making the animation difficult to compose with richer Astro markup or maintain as a component.

- Observation: Starlight 0.41.2 exposes `Header` and `Hero` as supported component overrides while retaining its own page frame, search dialog, social links, theme selector, and mobile menu.
  Evidence: `docs/node_modules/@astrojs/starlight/components/Page.astro` imports these through `virtual:starlight/components/*`, and `docs/node_modules/@astrojs/starlight/utils/user-config.ts` accepts a `components` map.

- Observation: The first desktop render matched the intended hierarchy, but the long word “intelligence” and the original “Read the overview” action exceeded the mobile visual measure even though the document itself had no horizontal scroll.
  Evidence: At a 390-pixel test viewport, `document.documentElement.scrollWidth` equaled `clientWidth`, while the screenshot showed glyph and button content clipped by the hero's intentional overflow boundary. The mobile display size and secondary label were shortened before final validation.

## Decision Log

- Decision: Translate the visual references into a “semantic terrain” rather than use a generated or photographic landscape.
  Rationale: Analyzer graph lines, nodes, and query signals are specific to Bifrost and can be delivered as small deterministic SVG and CSS with a useful reduced-motion state.
  Date/Author: 2026-07-20 / Codex

- Decision: Override only Starlight's `Hero` and `Header`; restyle the existing sidebar and table of contents with user CSS rather than replacing them.
  Rationale: This preserves Starlight's accessible navigation behavior and future compatibility while giving the highest-visibility parts a bespoke product identity.
  Date/Author: 2026-07-20 / Codex

- Decision: Keep the full terrain on the landing page and use only a subtle grid and localized red light on article pages.
  Rationale: The landing page benefits from spectacle, but persistent illustration behind long-form documentation would reduce legibility and create visual fatigue.
  Date/Author: 2026-07-20 / Codex

- Decision: Use a purely typographic capability deck and mirror the sidebar's product-section order in the desktop header.
  Rationale: The small multicolor Starlight icons competed with the more restrained terrain language, while matching MCP, LSP, and Querying order across both navigation surfaces makes the information architecture easier to scan.
  Date/Author: 2026-07-20 / Codex

- Decision: Make each capability block one accessible link rather than place uneven inline links inside only some descriptions.
  Rationale: A full-card link gives every capability an equally clear destination and a consistent directional affordance. The selected targets are the language capability matrix, querying overview, querying tool-selection table for usage graphs, and interface-selection guide for agent workflows.
  Date/Author: 2026-07-20 / Codex

- Decision: Preserve the floating query console but keep it entirely outside the headline's horizontal measure.
  Rationale: At the reported 1,545-pixel viewport the console overlapped the heading by about 39 pixels. Narrowing it to 34% retains the frosted layer over the terrain while leaving a deliberate gap and making the title unambiguously complete.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

The finished landing page now leads with “Code intelligence for AI,” a red semantic terrain, a small structural-query result panel, and concise evidence for structural queries, usage graphs, and repository-scale context. The prior large inline SVG was replaced by a maintainable Astro hero component with deterministic CSS-only movement and a complete reduced-motion state. The capability deck now reinforces the deeper analysis edge instead of repeating generic static-analysis language.

The shared documentation frame now uses a centered product rail with primary sections, search, GitHub, and theme controls. Article pages retain Starlight's behavior while gaining an inset sidebar, quieter selected-link indicator, and contained table of contents. The mobile view keeps search and menu as separate visible controls; the menu was exercised successfully after the responsive layout correction.

Validation completed with zero Astro errors, warnings, or hints; 55 static pages built; Pagefind indexed all 55; and 5,007 internal links passed against the final `origin/master` base. Browser inspection found no warning or error logs and no horizontal overflow at desktop or mobile widths. The review server returned HTTP 200 at `http://127.0.0.1:4321/` at completion.

## Context and Orientation

The documentation site is an Astro project rooted at `docs/` and uses the Starlight documentation theme. `docs/astro.config.mjs` owns Starlight configuration, navigation, social metadata, and the custom stylesheet registration. `docs/src/content/docs/index.mdx` is the splash page. Its current frontmatter asks Starlight to render a stock hero containing a large inline animated SVG. `docs/src/styles/brokk.css` defines Bifrost's black, warm-white, and red palette as well as the present hero animation and card styling.

A Starlight component override is a repository-owned Astro component selected in `docs/astro.config.mjs` instead of the package's default component. The new `docs/src/components/BifrostHero.astro` will replace only the stock hero on pages that opt into hero frontmatter. The new `docs/src/components/BifrostHeader.astro` will retain Starlight's built-in search, social, theme, language, and mobile-menu components while arranging them inside Bifrost-specific chrome.

The “semantic terrain” is an SVG scene whose perspective lines represent a repository-scale analysis graph. It is decorative and therefore hidden from assistive technology; nearby real text communicates the product features. Motion will use CSS transforms, opacity, and dash offsets, with a static complete scene under `prefers-reduced-motion: reduce`.

## Plan of Work

Create `docs/src/components/BifrostHero.astro`. It will read the current page's hero configuration, render a concise product eyebrow, the primary message “Code intelligence for AI,” supporting copy, the existing action buttons, and a short proof strip for structural queries, usage graphs, and repository-scale analysis. Behind and beside that content, render an SVG terrain with perspective mesh lines, graph nodes, an analysis route, and a small translucent query-result panel. Keep all meaningful text as HTML rather than SVG text.

Create `docs/src/components/BifrostHeader.astro`. Preserve the built-in Starlight `SiteTitle`, `Search`, `SocialIcons`, `ThemeSelect`, and `LanguageSelect` components. Add a compact desktop-only primary navigation for Overview, Capabilities, Query, and MCP. Use the current route to mark the active item, and construct links from Starlight's configured site-title base so both the development root and production `/bifrost/` base work.

Update `docs/src/content/docs/index.mdx` to remove the large inline SVG and use concise hero metadata consumed by the custom hero. Keep the current cards and release version strip, but tune their surrounding presentation through CSS so they feel connected to the scene.

Update `docs/src/styles/brokk.css` to establish the header rail, landing scene, subdued article-page atmosphere, inset sidebar, narrow red active-link indicator, and framed right-hand table of contents. Add responsive rules that collapse the proof strip and query panel cleanly and preserve all existing mobile navigation. Add reduced-motion rules for every new animation.

Update `docs/astro.config.mjs` to register the custom `Header` and `Hero` component paths. Do not replace Starlight's PageFrame, Sidebar, Search, or table-of-contents behavior.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/a7c8/bifrost`.

After editing, validate the docs source with:

    npm --prefix docs run check

Expect Astro to report no errors. Then run:

    npm --prefix docs run build

Expect Astro to build the static site under `docs/dist`, Pagefind to index the output, and `scripts/check-links.mjs` to report that internal links are valid.

For visual verification, start:

    npm --prefix docs run dev -- --host 127.0.0.1

Open the reported local URL at `/` and `/capabilities/`. Inspect desktop and mobile viewport screenshots. The landing page must preserve a clear text region while showing the semantic terrain and query panel; the article page must show the new header, sidebar active rail, and framed table of contents without text clipping or horizontal overflow.

## Validation and Acceptance

The home page is accepted when its first viewport clearly says “Code intelligence for AI,” includes working “Choose Bifrost” and “Overview” actions, displays a technical terrain rather than a disconnected logo animation, and shows the existing four capability cards below the hero. With motion reduction enabled, the complete scene must remain visible without animation.

A content page is accepted when search, GitHub, theme controls, desktop navigation, mobile menu, sidebar navigation, and table-of-contents links remain usable. At desktop width, the header reads as a centered product rail; the selected sidebar item uses a red leading accent with a quiet dark fill instead of a solid bright block; and the table of contents has a subtle bordered surface. At mobile width, the desktop product links and wide query panel may disappear, but the title, search button, menu button, article content, and primary hero actions must remain accessible without horizontal scrolling.

The implementation is complete only after `npm --prefix docs run check` and `npm --prefix docs run build` pass and current browser screenshots prove both page types at both viewport classes.

## Idempotence and Recovery

All edits are source-controlled text changes and can be reapplied safely. Astro's generated `docs/dist` and cache outputs are not source files and must remain uncommitted. If a component override prevents the site from compiling, remove only its entry from the Starlight `components` map to return to the stock component while correcting the repository-owned Astro file. The development server can be stopped with Ctrl-C and restarted with the same command without changing repository state.

## Artifacts and Notes

The baseline is commit `2a7d668c5b64cddec97257bc131729e605f2348d`, which is also the fetched `origin/master` at the start of this work. The existing live visual language is a 32-pixel grid, a localized red radial glow, warm off-white text, Rajdhani body type, JetBrains Mono code type, and Staatliches display headings. The redesign should evolve that system rather than introduce unrelated purple, blue, or pastoral imagery.

## Interfaces and Dependencies

No new package dependency is required. `BifrostHeader.astro` will consume Starlight's virtual components and `Astro.locals.starlightRoute`. `BifrostHero.astro` will consume `Astro.locals.starlightRoute.entry.data.hero` and Starlight's exported `LinkButton` component. Both are server-rendered Astro components. All interactivity and animation will remain CSS-only so the finished page adds no client-side JavaScript beyond Starlight's existing navigation and search behavior.

Revision note (2026-07-20 11:34Z): Created the plan after inspecting the exact current worktree and the installed Starlight component boundaries, so implementation and acceptance are tied to the current docs architecture.

Revision note (2026-07-20 11:47Z): Recorded the first responsive-render discovery and the resulting breakpoint correction so the plan reflects visual evidence rather than source-level assumptions.

Revision note (2026-07-20 11:49Z): Marked implementation, responsive verification, production validation, and the live review server complete, and recorded the observable final outcome.

Revision note (2026-07-20 11:54Z): Recorded the first browser-review follow-up: a typographic card deck and cross-navigation ordering consistency.

Revision note (2026-07-20 12:00Z): Recorded the second browser-review follow-up and the decision to make each capability block a single accessible documentation link.

Revision note (2026-07-20 12:05Z): Recorded the measured medium-width collision and the constrained console-width correction.

Revision note (2026-07-20 12:09Z): Recorded the linked Brokk byline requested during browser review.

Revision note (2026-07-20 12:15Z): Replaced the illustrative pseudo-query and fabricated latency with valid RQL and result labels that match the structural call-query domain.
