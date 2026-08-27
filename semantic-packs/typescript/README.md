# TypeScript standard-library pack

`typescript-7.0.2.json` pins the canonical TypeScript 7.0.2 standard-library
declarations. TypeScript 7 publishes the compiler package and the platform
package containing `lib/*.d.ts` separately; the public build script combines
the root `typescript` manifest with the official Linux x64 companion's
declaration files into the exact source set named by the specification.

The source-set digest is over `package.json` and the canonical `lib.*.d.ts`
files. The compatibility alias `lib.es6.d.ts` and aggregate `lib.d.ts` are
intentionally not shards: `es6` is an alias for `es2015`, while `lib.d.ts`
only composes the selected libraries. The complete upstream notice is
retained in `notices/typescript-7.0.2.txt`.

Build the pack with:

```sh
scripts/public/build-pinned-typescript-semantic-packs.sh OUTPUT_DIR WORK_DIR
```
