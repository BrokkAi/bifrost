---
title: Open Pack Acquisition
description: Select, verify, record, and replay open policy pack releases.
---

`bifrost prepare-open-packs` selects and verifies a policy pack release and its
declared dependencies. It writes a machine-readable outcome for both success and
typed acquisition failure. Hosts can use that outcome to record the selection,
inspect a failure class, and replay the same release later.

## Run the command

Provide a cache directory and two output paths:

```sh
bifrost prepare-open-packs \
  --cache-dir /var/cache/bifrost/open-packs \
  --request-path request.json \
  --receipt-path outcome.json \
  --env-path environment.json
```

`--request-path` is optional. Without it, Bifrost uses the default public-pack
request or the strict request in `PACK_SOURCE`. A nonempty `PACK_SOURCE` cannot
be combined with `--request-path`. `--identity-only` prints the cache identity
and cannot be combined with `--request-path` or either output path.

The command writes the acquisition outcome to `--receipt-path`. A successful
selection also writes selected roots to `--env-path`. A policy-only pack has no
native semantic bundle, so its environment file omits
`BIFROST_OPEN_SEMANTIC_PACK_BUNDLE`.

Exit codes are:

| Code | Meaning |
| --- | --- |
| `0` | A pack selection was verified and recorded. |
| `1` | A typed acquisition failure was recorded in the outcome. |
| `2` | The invocation or an output failed validation. No outcome is written. |

An unreadable request file is an invocation error and exits `2`. A readable
request that fails parsing or validation produces a typed outcome and exits
`1`. Invalid JSON, unknown fields, and contradictory options use
`invalid-configuration`; invalid repository URLs, digests, SemVer versions, or
version requirements use `invalid-source`.

## Request document

A request uses `request_schema_version: 1`, a root `pack_id`, its GitHub
repository URL, and a `selection`. Unknown fields are rejected. The repository
must be an HTTPS GitHub repository URL without credentials, a port, query, or
fragment. An optional `inventory` object pins a trusted HTTPS inventory mirror
by URL and SHA-256 digest. Versions use SemVer: `major.minor.patch`, with
optional prerelease or build metadata.

Preferred mode keeps an eligible `preferred_version`; if that version is
ineligible or absent, it selects the highest eligible version. `allowed_versions`
is a SemVer requirement and defaults to any version. It is matched against
the release version without its prerelease identifiers, so `>=1.0.0, <2.0.0`
admits `1.1.0-rc.1` when the channel allows prereleases. `channel` defaults to
`stable`; `stable` excludes both GitHub prereleases and SemVer prerelease
versions, while `prerelease` admits both.

This request prefers public rules release `0.1.4`, while accepting any stable
release in the stated range if that preference is no longer eligible:

```json
{
  "request_schema_version": 1,
  "pack_id": "bifrost.public.rules",
  "repository": "https://github.com/BrokkAi/bifrost-packs",
  "selection": {
    "mode": "preferred",
    "preferred_version": "0.1.4",
    "allowed_versions": ">=0.1.0, <1.0.0",
    "channel": "stable"
  }
}
```

This request asks for the private premium pack. The caller must have permission
to read the repository:

```json
{
  "request_schema_version": 1,
  "pack_id": "bifrost.premium",
  "repository": "https://github.com/BrokkAi/bifrost-premium-packs",
  "selection": {
    "mode": "preferred",
    "allowed_versions": ">=0.3.0, <1.0.0",
    "channel": "stable"
  }
}
```

Strict mode names exactly one release by `release_version` and
`manifest_sha256`. It never selects an alternative. In strict mode,
`dependencies` must pin every dependency declared by that release. Every pin
requires `pack_id`, `repository`, and `manifest_sha256`; `release_version` is
optional. Without a version, the pin constrains the dependency by pack ID and
manifest digest, and the version declared by the selected root manifest is
accepted. If a pin supplies a version, that version must also match. Preferred
mode applies the same pin checks to eligible candidates. Replay requests always
include each dependency's exact `release_version`.

The selector checks the channel and version range, engine compatibility,
dependencies, dependency pins, and release qualification. It keeps the
preferred version when it passes every check; otherwise it selects the highest
eligible SemVer version. Valid inventories cannot contain two releases of one
pack ID with equal SemVer precedence and different manifest digests. A
re-release with changed manifest bytes is a distinct release: preferred mode
can select it as the current release, while a strict request or replay fails
with an integrity error if its pinned digest no longer matches.

A strict selection has this shape. Replace the digest placeholder with the
64-character SHA-256 digest from the release manifest:

```json
{
  "mode": "strict",
  "release_version": "0.1.4",
  "manifest_sha256": "<64 hexadecimal characters>"
}
```

## Outcome document

Every invocation that passes argument validation writes an outcome document.
It contains `outcome_schema_version: 1`, `status`, engine version, build
identity and executable digest, the parsed request or `null`, rejections,
inventory details when known, and a creation time.

For `status: "selected"`, `selection` contains the selection ID, the selection
reason (`strict-lock`, `preferred-version`, or `highest-eligible`), whether the
cache was reused, the receipt path, the selected policy and semantic roots, and
the full selection receipt. `failure` is `null`. The top-level `rejections` and
`inventory` describe this run; the embedded receipt keeps the inventory
snapshot, request, and rejections of the run that first produced the
selection, and warm reuse compares only the selected content. For `status: "failed"`,
`selection` is `null` and `failure` contains a stable class, retryability flag,
and sanitized message. The immutable selection receipt includes the selected
release records, the inventory snapshot digest, and a strict `replay` request.

Copy `selection.receipt.replay` into a request file to ask for the same root and
dependency manifest digests again. Replay selects those exact bytes or returns
a typed failure; it does not fall back to a newer version.

## Failure classes

Retryability describes whether repeating the same request may succeed without
changing its inputs or credentials. The `retryable` flag in the outcome is
authoritative; the table gives the usual value for each class.

| Class | Retryable | Caller action |
| --- | --- | --- |
| `invalid-configuration` | No | Correct the request, flags, or incompatible environment settings. |
| `invalid-source` | No | Correct the repository or inventory URL, digest, version, or range. |
| `invalid-profile` | No | Use a valid engine profile or a compatible engine build. |
| `invalid-manifest` | No | Have the publisher correct the release manifest. |
| `missing-strict-selection` | No | Check the pinned release or create a new request for an available release. |
| `incompatible-strict-selection` | No | Use a release that meets the engine and dependency contract. |
| `no-compatible-release` | No | Change the allowed range or channel, or publish a compatible release. |
| `integrity` | No | Treat the selected bytes as untrusted and investigate the digest mismatch. |
| `access-denied` | No | Check repository visibility and provide a credential with read access. |
| `unavailable` | Usually | Retry later; this class covers temporary network failures and a cached inventory that cannot prove absence. A registry listing that exceeds the supported page limit is not retryable. |
| `offline-cache-miss` | No | Enable network access, or populate the verified cache before retrying offline. |
| `pending` | No | Wait for release qualification to finish, then request again. |
| `unqualified` | No | Select another qualified release or resolve the failed qualification. |

`BIFROST_OPEN_PACKS_OFFLINE=1` restricts acquisition to the verified local
cache. `BIFROST_OPEN_PACKS_REFRESH=1` forces inventory discovery instead of
reusing the cached inventory. Offline and refresh cannot be enabled together.
The cache normally reuses a verified inventory for one hour and stores verified
artifacts by digest.

Private source content is stored below `sources/<identity>` under the cache
root. Its source identity includes the pack ID, repository, and inventory
identity, which keeps private content separate from the public cache root.
Do not publish caches containing private content to a shared cache.

## Credentials

`PACK_TOKEN` is the only credential used to read private pack repositories. It
is sent in the authorization header for GitHub API and asset requests. Never
put the token in a URL or request document. Receipts, outcomes, and log messages
must not contain the token.
