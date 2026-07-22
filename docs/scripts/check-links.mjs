import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeBase } from '../rehype-base-path-links.mjs';

const docsRoot = fileURLToPath(new URL('..', import.meta.url));
const distRoot = join(docsRoot, 'dist');
const base = normalizeBase(process.env.PUBLIC_DOCS_BASE ?? '/');
const origin = 'https://docs.invalid';

function walkFiles(directory) {
  const pending = [directory];
  const files = [];

  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current)) {
      const path = join(current, entry);
      if (statSync(path).isDirectory()) pending.push(path);
      else files.push(path);
    }
  }

  return files;
}

function publicPathFor(file) {
  const path = relative(distRoot, file).split(sep).join('/');
  const prefix = base === '/' ? '' : base;
  if (path === 'index.html') return `${prefix}/`;
  if (path.endsWith('/index.html')) return `${prefix}/${path.slice(0, -'index.html'.length)}`;
  return `${prefix}/${path}`;
}

function targetFileFor(pathname) {
  if (base !== '/' && pathname !== base && !pathname.startsWith(`${base}/`)) return null;

  const sitePath = decodeURIComponent(base === '/' ? pathname : pathname.slice(base.length));
  const relativePath = sitePath.replace(/^\/+/, '');
  const candidates = [];

  if (relativePath === '' || sitePath.endsWith('/')) {
    candidates.push(join(distRoot, relativePath, 'index.html'));
  } else {
    candidates.push(join(distRoot, relativePath));
    if (!extname(relativePath)) {
      candidates.push(join(distRoot, `${relativePath}.html`));
      candidates.push(join(distRoot, relativePath, 'index.html'));
    }
  }

  return candidates.find(existsSync) ?? null;
}

function decodeHtml(value) {
  return value
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>');
}

function idsFor(file, cache) {
  if (cache.has(file)) return cache.get(file);

  const ids = new Set();
  const html = readFileSync(file, 'utf8');
  for (const match of html.matchAll(/\b(?:id|name)="([^"]+)"/g)) {
    ids.add(decodeHtml(match[1]));
  }
  cache.set(file, ids);
  return ids;
}

if (!existsSync(distRoot)) {
  console.error('docs/dist does not exist; run the docs build first.');
  process.exit(1);
}

const htmlFiles = walkFiles(distRoot).filter((file) => file.endsWith('.html'));
const idCache = new Map();
const failures = new Set();
let checked = 0;

for (const sourceFile of htmlFiles) {
  const html = readFileSync(sourceFile, 'utf8');
  const source = relative(distRoot, sourceFile).split(sep).join('/');
  const pageUrl = new URL(publicPathFor(sourceFile), origin);

  for (const match of html.matchAll(/\b(?:href|src)="([^"]*)"/g)) {
    const rawValue = decodeHtml(match[1]);
    if (
      rawValue === '' ||
      rawValue.startsWith('//') ||
      /^[a-z][a-z\d+.-]*:/i.test(rawValue)
    ) {
      continue;
    }

    checked += 1;

    if (
      base !== '/' &&
      rawValue.startsWith('/') &&
      rawValue !== base &&
      !rawValue.startsWith(`${base}/`)
    ) {
      failures.add(`${source}: ${rawValue} omits deployment base ${base}`);
      continue;
    }

    const targetUrl = new URL(rawValue, pageUrl);
    const targetFile = targetFileFor(targetUrl.pathname);
    if (!targetFile) {
      failures.add(`${source}: ${rawValue} does not resolve to a built file`);
      continue;
    }

    if (targetUrl.hash && targetFile.endsWith('.html')) {
      let fragment;
      try {
        fragment = decodeURIComponent(targetUrl.hash.slice(1));
      } catch {
        failures.add(`${source}: ${rawValue} has an invalid encoded fragment`);
        continue;
      }

      if (fragment && !idsFor(targetFile, idCache).has(fragment)) {
        failures.add(`${source}: ${rawValue} points to a missing fragment`);
      }
    }
  }
}

if (failures.size > 0) {
  console.error(`Found ${failures.size} broken internal docs link(s):`);
  for (const failure of [...failures].sort()) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Checked ${checked} internal docs links across ${htmlFiles.length} HTML files (base: ${base}).`);
