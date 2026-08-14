import { copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = resolve(repoRoot, "packaging/bifrost-cli/.generated-licenses");
const required = [
  "LICENSE.md",
  "licenses/GPL-3.0.md",
  "licenses/LGPL-3.0.md",
  "licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt",
];
const generated = "licenses/THIRD_PARTY_LICENSES.html";

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });

for (const relativePath of required) {
  const source = resolve(repoRoot, relativePath);
  if (!existsSync(source)) {
    throw new Error(`Required CLI wheel license file is missing: ${relativePath}`);
  }
  copyFileSync(source, resolve(output, basename(source)));
}

const generatedSource = resolve(repoRoot, generated);
if (existsSync(generatedSource)) {
  copyFileSync(generatedSource, resolve(output, basename(generatedSource)));
}
