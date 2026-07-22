# Security Policy

## Supported Versions

Security fixes are applied to the latest released version and the current default branch.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| Earlier releases | ❌ |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Use GitHub's private vulnerability reporting flow:

[Report a vulnerability privately](https://github.com/BrokkAi/bifrost/security/advisories/new)

Please include, where possible:

- The affected version or commit
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- Any known mitigations or suggested remediation
- Whether you would like public credit after disclosure

We will review the report, request additional information if necessary, and coordinate remediation and disclosure with you. Please allow time for a fix to be prepared and released before publishing details.

## GitHub Actions Security Policy

Every external `uses:` reference in `.github/workflows/` must use a full, lowercase, 40-character commit SHA followed by a comment naming the reviewed upstream tag or branch. Local actions and reusable workflows beginning with `./` are exempt because their code is part of the same reviewed commit.

Workflows default to `contents: read`. A job may grant write or OIDC permissions only for the publishing or deployment step that requires them. Checkout credentials must not persist between steps, secrets must be scoped to the smallest possible step, and publishing or deployment jobs must not consume writable Actions caches.

Run the enforced security audit locally with:

```bash
bash scripts/check-github-actions-security.sh
```

The script runs the pinned zizmor 1.28.0 release offline, requires strict workflow collection, and fails on findings of medium severity or higher. The companion Node test enforces immutable references and readable comments:

```bash
node --test scripts/github-actions-policy.test.mjs
```

Action updates are deliberate, reviewed maintenance. Resolve the desired upstream tag in the action's authoritative repository, verify the commit, update both the SHA and its comment, and run both checks. This repository intentionally does not use an automated action-update bot.
