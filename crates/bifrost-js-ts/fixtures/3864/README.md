# Issue #3864 ownership contract

These small test-only reductions describe independent bundled module factories
assigning `exports.default`. They are not product packs or upstream snapshots.

`bundle.js` contains two function exports. `mixed-wrappers.js` adds an object
export with the same `getStyle` member name. Each factory must keep its own
structured declaration and member ownership, and every owner must contain its
members. Both reduce the bundled-wrapper shape documented in issue #3864.
