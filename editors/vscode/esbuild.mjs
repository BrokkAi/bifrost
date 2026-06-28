import * as esbuild from "esbuild";

const watch = process.argv.includes("--watch");

/** @type {esbuild.BuildOptions} */
const extensionOptions = {
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "out/extension.js",
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node18",
  sourcemap: true,
  minify: !watch
};

if (watch) {
  const context = await esbuild.context(extensionOptions);
  await context.watch();
  console.log("Watching Bifrost VS Code extension...");
} else {
  await esbuild.build(extensionOptions);
  console.log("Build complete.");
}

