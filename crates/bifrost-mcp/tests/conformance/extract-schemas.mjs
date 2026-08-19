// Extract the official MCP spec JSON schemas bundled inside the pinned
// @modelcontextprotocol/conformance dist bundle, and check the extraction
// against the files committed in schemas/.
//
// The 2026-07-28 revision was still the spec repository's moving `draft/`
// directory when the pinned conformance version was published, so the only
// stable definition of "the official schema the gate judges against" is the
// snapshot the pinned runner itself validates with. Extracting from that exact
// artifact keeps the Rust wire-schema gate and the official runner in agreement
// and gives one thing to bump.
//
// Usage:
//   node extract-schemas.mjs            compare schemas/ with a fresh
//                                       extraction; exit 1 on any drift
//   node extract-schemas.mjs --write     regenerate schemas/
//
// run.mjs imports `extractSchemas` and `compareSchemas` so the gate performs the
// identical comparison without shelling out.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_BUNDLE = path.join(
  HERE,
  'node_modules',
  '@modelcontextprotocol',
  'conformance',
  'dist',
  'index.js',
);
export const DEFAULT_SCHEMA_DIR = path.join(HERE, 'schemas');

// Parse the object literal assigned to minified variable `name` with the
// strict data-literal parser below. The bundle is generated, not hand-written,
// so the literal is pure data (objects, arrays, strings, numbers, booleans,
// null); anything outside that grammar is a hard error, never executed code.
function extractObjectLiteral(source, name) {
  const re = new RegExp('[,;\\s]' + name.replace(/\$/g, '\\$') + '=\\{');
  const m = re.exec(source);
  if (!m) return null;
  return parseDataLiteral(source, m.index + m[0].length - 1);
}

// A recursive-descent parser for the subset of JavaScript expression syntax a
// minifier emits for pure data: object and array literals, identifier or
// quoted keys, double-/single-/backtick-quoted strings (templates carry
// literal newlines but no interpolation), numbers, `true`/`false` (also the
// minified `!0`/`!1` forms), and `null`. This replaces evaluating bundle text:
// the grammar is closed, so a bundle change that introduces anything else
// fails loudly here instead of executing.
function parseDataLiteral(source, start) {
  let i = start;
  const fail = (what) => {
    throw new Error(
      `schema literal parse error at offset ${i}: ${what} (context: ${JSON.stringify(source.slice(i, i + 40))})`,
    );
  };
  const ws = () => {
    while (i < source.length && /\s/.test(source[i])) i++;
  };
  const stringEscape = () => {
    const c = source[++i];
    i++;
    switch (c) {
      case 'n':
        return '\n';
      case 't':
        return '\t';
      case 'r':
        return '\r';
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case 'v':
        return '\v';
      case '0':
        return '\0';
      case 'x': {
        const hex = source.slice(i, i + 2);
        i += 2;
        return String.fromCharCode(parseInt(hex, 16));
      }
      case 'u': {
        if (source[i] === '{') {
          const end = source.indexOf('}', i);
          const code = parseInt(source.slice(i + 1, end), 16);
          i = end + 1;
          return String.fromCodePoint(code);
        }
        const hex = source.slice(i, i + 4);
        i += 4;
        return String.fromCharCode(parseInt(hex, 16));
      }
      case '\n':
        return '';
      default:
        return c;
    }
  };
  const string = () => {
    const quote = source[i];
    i++;
    let out = '';
    while (i < source.length) {
      const c = source[i];
      if (c === '\\') {
        out += stringEscape();
        continue;
      }
      if (c === quote) {
        i++;
        return out;
      }
      if (quote === '`' && c === '$' && source[i + 1] === '{') {
        fail('template interpolation is not data');
      }
      if (quote !== '`' && (c === '\n' || c === '\r')) {
        fail('unterminated string');
      }
      out += c;
      i++;
    }
    return fail('unterminated string');
  };
  const value = () => {
    ws();
    const c = source[i];
    if (c === '{') return object();
    if (c === '[') return array();
    if (c === '"' || c === "'" || c === '`') return string();
    if (c === '!') {
      const digit = source[i + 1];
      i += 2;
      if (digit === '0') return true;
      if (digit === '1') return false;
      return fail('unexpected ! expression');
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/.exec(source.slice(i));
      if (!m) return fail('malformed number');
      i += m[0].length;
      return Number(m[0]);
    }
    const word = /^[A-Za-z_$][\w$]*/.exec(source.slice(i));
    if (word) {
      i += word[0].length;
      if (word[0] === 'true') return true;
      if (word[0] === 'false') return false;
      if (word[0] === 'null') return null;
      return fail(`bare identifier '${word[0]}' is not data`);
    }
    return fail('unexpected character');
  };
  const key = () => {
    ws();
    const c = source[i];
    if (c === '"' || c === "'" || c === '`') return string();
    const word = /^[A-Za-z_$][\w$]*/.exec(source.slice(i));
    if (!word) return fail('expected a property key');
    i += word[0].length;
    return word[0];
  };
  const object = () => {
    i++; // consume {
    const out = {};
    ws();
    if (source[i] === '}') {
      i++;
      return out;
    }
    for (;;) {
      const k = key();
      ws();
      if (source[i] !== ':') fail("expected ':' after property key");
      i++;
      out[k] = value();
      ws();
      if (source[i] === ',') {
        i++;
        continue;
      }
      if (source[i] === '}') {
        i++;
        return out;
      }
      fail("expected ',' or '}' in object literal");
    }
  };
  const array = () => {
    i++; // consume [
    const out = [];
    ws();
    if (source[i] === ']') {
      i++;
      return out;
    }
    for (;;) {
      out.push(value());
      ws();
      if (source[i] === ',') {
        i++;
        continue;
      }
      if (source[i] === ']') {
        i++;
        return out;
      }
      fail("expected ',' or ']' in array literal");
    }
  };
  ws();
  if (source[i] !== '{') fail('expected an object literal');
  return object();
}

// Returns a Map of revision -> file text (pretty-printed JSON with a trailing
// newline), in the order the bundle's version map declares them.
export function extractSchemas(bundlePath = DEFAULT_BUNDLE) {
  const source = fs.readFileSync(bundlePath, 'utf8');
  const mapMatch = source.match(
    /const ([A-Za-z_$]{1,4})=\{"2025-03-26":([A-Za-z_$]{1,4}),"2025-06-18":([A-Za-z_$]{1,4}),"2025-11-25":([A-Za-z_$]{1,4}),\[([A-Za-z_$]{1,4})\]:([A-Za-z_$]{1,4})\}/,
  );
  if (!mapMatch) {
    throw new Error(`schema version map not found in ${bundlePath}`);
  }
  const draftVarName = mapMatch[5].replace(/\$/g, '\\$');
  const draftMatch = source.match(new RegExp('\\b' + draftVarName + '=`([0-9-]+)`'));
  if (!draftMatch) {
    throw new Error(`draft revision constant ${mapMatch[5]} not found in ${bundlePath}`);
  }
  const variables = new Map([
    ['2025-03-26', mapMatch[2]],
    ['2025-06-18', mapMatch[3]],
    ['2025-11-25', mapMatch[4]],
    [draftMatch[1], mapMatch[6]],
  ]);

  const out = new Map();
  for (const [revision, variable] of variables) {
    const schema = extractObjectLiteral(source, variable);
    if (!schema) {
      throw new Error(`extraction failed for ${revision} (bundle variable ${variable})`);
    }
    const defs = schema.$defs ?? schema.definitions;
    if (!defs || !('JSONRPCMessage' in defs)) {
      throw new Error(`extracted object for ${revision} does not look like an MCP schema`);
    }
    out.set(revision, JSON.stringify(schema, null, 2) + '\n');
  }
  return out;
}

export function schemaFileName(revision) {
  return `mcp-schema-${revision}.json`;
}

// Byte-compares a fresh extraction with the committed files. Returns an array of
// human-readable problem descriptions; empty means no drift.
export function compareSchemas(bundlePath = DEFAULT_BUNDLE, schemaDir = DEFAULT_SCHEMA_DIR) {
  const extracted = extractSchemas(bundlePath);
  const problems = [];
  for (const [revision, text] of extracted) {
    const file = path.join(schemaDir, schemaFileName(revision));
    if (!fs.existsSync(file)) {
      problems.push(`${file}: missing; re-extraction produced this revision`);
      continue;
    }
    const onDisk = fs.readFileSync(file, 'utf8');
    if (onDisk !== text) {
      problems.push(
        `${file}: differs from re-extraction (${onDisk.length} bytes on disk, ${text.length} extracted)`,
      );
    }
  }
  const expected = new Set([...extracted.keys()].map(schemaFileName));
  for (const name of fs.readdirSync(schemaDir)) {
    if (name.endsWith('.json') && !expected.has(name)) {
      problems.push(`${path.join(schemaDir, name)}: not produced by re-extraction; stale file`);
    }
  }
  return problems;
}

function main() {
  const write = process.argv.includes('--write');
  if (write) {
    const extracted = extractSchemas();
    fs.mkdirSync(DEFAULT_SCHEMA_DIR, { recursive: true });
    for (const [revision, text] of extracted) {
      const file = path.join(DEFAULT_SCHEMA_DIR, schemaFileName(revision));
      fs.writeFileSync(file, text);
      const schema = JSON.parse(text);
      const defs = schema.$defs ?? schema.definitions;
      console.log(
        `wrote ${path.relative(HERE, file)}: $schema=${schema.$schema} defs=${Object.keys(defs).length}`,
      );
    }
    return 0;
  }
  const problems = compareSchemas();
  if (problems.length > 0) {
    console.error('schema drift against the pinned conformance bundle:');
    for (const p of problems) console.error(`  ${p}`);
    console.error('run `node extract-schemas.mjs --write` if the pin bump is deliberate');
    return 1;
  }
  console.log('schemas match the pinned conformance bundle');
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main());
}
