import { chmodSync, writeFileSync } from "node:fs";

export function writeExecutable(filePath, contents) {
  writeFileSync(filePath, contents);
  chmodSync(filePath, 0o755);
}
