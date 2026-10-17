import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

export async function createQualificationBundle({ prefix, files, identity, generateManifest }) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const bundleDir = path.join(root, "bundle");
  await fs.mkdir(bundleDir);
  for (const [relativePath, contents] of Object.entries(files)) {
    const filePath = path.join(bundleDir, relativePath);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, contents);
  }
  const manifestPath = path.join(bundleDir, "release-qualification.json");
  generateManifest({ bundleDir, identity, outputPath: manifestPath });
  return { bundleDir, manifestPath };
}
