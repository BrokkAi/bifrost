#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

function readCargoVersion() {
  const cargoToml = readFileSync(new URL('../Cargo.toml', import.meta.url), 'utf8');
  const match = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error('Could not find package version in Cargo.toml');
  }
  return match[1];
}

function parseReleaseTag(rawTag) {
  if (!rawTag) return null;
  const tag = rawTag.replace(/^refs\/tags\//, '');
  const version = tag.startsWith('v') ? tag.slice(1) : '';
  if (!/^\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`Docs release tag must look like v<semver>, got '${rawTag}'`);
  }
  return { tag, version };
}

function currentReleaseTag() {
  if (process.env.GITHUB_EVENT_NAME === 'pull_request') {
    return '';
  }
  if (process.env.RELEASE_TAG_INPUT) {
    return process.env.RELEASE_TAG_INPUT;
  }
  if (process.env.GITHUB_REF_TYPE === 'tag') {
    return process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || '';
  }
  if (process.env.GITHUB_REF?.startsWith('refs/tags/')) {
    return process.env.GITHUB_REF;
  }
  return latestReleaseTag();
}

function latestReleaseTag() {
  const output = execFileSync('git', ['tag', '--list', 'v*.*.*', '--sort=-v:refname'], { encoding: 'utf8' });
  const tag = output
    .split('\n')
    .map((line) => line.trim())
    .find(Boolean);
  if (!tag) {
    throw new Error('Could not find any release tags matching v*.*.*');
  }
  return tag;
}

const release = parseReleaseTag(currentReleaseTag());
const version = release?.version ?? readCargoVersion();
const tag = release?.tag ?? '';
const label = tag || `development-${version}`;
const releaseUrl = tag ? `https://github.com/BrokkAi/bifrost/releases/tag/${tag}` : '';

const outputs = {
  version,
  tag,
  label,
  is_release: tag ? 'true' : 'false',
  release_url: releaseUrl,
};

if (process.env.GITHUB_OUTPUT) {
  const lines = Object.entries(outputs).map(([key, value]) => `${key}=${value}`);
  await import('node:fs').then(({ appendFileSync }) => appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`));
} else {
  for (const [key, value] of Object.entries(outputs)) {
    console.log(`${key}=${value}`);
  }
}
