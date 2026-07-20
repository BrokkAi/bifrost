#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DISCORD_RELEASE_WEBHOOK_URL:-}" ]; then
  echo "Discord release announcements are not configured; skipping."
  exit 0
fi

for required_var in GH_TOKEN RELEASE_TAG GITHUB_REPOSITORY; do
  if [ -z "${!required_var:-}" ]; then
    echo "Missing required environment variable: ${required_var}." >&2
    exit 1
  fi
done

release_json="$(mktemp)"
payload_json="$(mktemp)"
trap 'rm -f "$release_json" "$payload_json"' EXIT

if ! gh release view --repo "$GITHUB_REPOSITORY" --json body,url -- "$RELEASE_TAG" > "$release_json"; then
  echo "::warning::Discord release announcement was not sent; the GitHub Release remains published."
  exit 1
fi

# Release notes are untrusted text. jq JSON-encodes them instead of allowing
# their contents to affect the shell command or the webhook payload shape.
if ! jq --arg tag "$RELEASE_TAG" '
  (.body // "") as $notes
  | ("**Bifrost " + $tag + " is out**\n" + .url) as $headline
  | ($headline + "\n\n") as $prefix
  | "\n\n… See the release for full notes." as $truncation
  | if $notes == "" then $headline
    elif (($prefix | length) + ($notes | length)) <= 1900 then $prefix + $notes
    else $prefix + $notes[0:(1900 - ($prefix | length) - ($truncation | length))] + $truncation
    end
  | {content: ., allowed_mentions: {parse: []}, flags: 4}
' "$release_json" > "$payload_json"; then
  echo "::warning::Discord release announcement was not sent; the GitHub Release remains published."
  exit 1
fi

if ! curl --fail-with-body --silent --show-error --max-time 15 \
  --request POST \
  --header 'Content-Type: application/json' \
  --data-binary @"$payload_json" \
  -- "$DISCORD_RELEASE_WEBHOOK_URL"; then
  echo "::warning::Discord release announcement was not sent; the GitHub Release remains published."
  exit 1
fi
