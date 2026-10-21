# brokk-bifrost-tools

Product-facing code intelligence APIs for Bifrost: navigation and usage search,
quality reports, diff analysis, relevance, summaries, and symbol rename.

This crate builds on `brokk-bifrost-analysis`. Keeping these surfaces separate
lets changes to product tools reuse the compiled analysis engine.
