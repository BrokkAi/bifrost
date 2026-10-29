#!/usr/bin/env bash
# Check what `bifrost prepare-open-packs` reported before the policy-scan
# action scans with the content it selected, and record how far that content
# is qualified.
#
# Usage: check-open-pack-selection.sh RECEIPT ENV_FILE QUALIFICATION_OUT
#
# The action accepts a `qualified` or a `compatible` receipt. The engine calls
# a selection `compatible` when every selected release has verified integrity
# but some release's behavior evidence is only `limited` or `pending`; it
# refuses a release with pending or failed integrity, or failed behavior,
# before it writes a receipt. This script asserts the integrity rule on every
# selected release itself, so the action's guarantee is visible here rather
# than resting on the installed engine. The release dry run runs this script
# on the action's default pin, so a pin the action would reject fails the
# release instead of every downstream scan (#7497).
#
# Every rejection prints a ::error:: line that names what was rejected and why.
# On success, QUALIFICATION_OUT receives {selection_id, status, releases}, and
# when GITHUB_STEP_SUMMARY is set, the job summary receives the same as a table.
set -euo pipefail

receipt="${1:?usage: check-open-pack-selection.sh RECEIPT ENV_FILE QUALIFICATION_OUT}"
env_file="${2:?usage: check-open-pack-selection.sh RECEIPT ENV_FILE QUALIFICATION_OUT}"
qualification="${3:?usage: check-open-pack-selection.sh RECEIPT ENV_FILE QUALIFICATION_OUT}"

# Receipt values come from a pack repository, so they are shown as JSON and
# escaped before they reach a workflow command.
defs='
def show: if type == "string" then . else tojson end;
def command: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
# A schema 2 release qualifies integrity and behavior separately. A schema 1
# release has one status, and only `qualified` is selectable, so it counts as
# verified integrity and qualified behavior.
def axes: .qualification as $q
  | if ($q | type) == "object" and ($q | has("integrity")) then
      {integrity: $q.integrity.status, behavior: $q.behavior.status}
    elif ($q | type) == "object" and $q.status == "qualified" then
      {integrity: "verified", behavior: "qualified"}
    else
      {integrity: (($q | objects | .status) // $q), behavior: (($q | objects | .status) // $q)}
    end;
'

receipt_problems='
if type != "object" then "open-pack receipt is a JSON \(type); the action requires an object"
elif .status != "selected" then "open-pack receipt status is \(.status | show); the action requires selected"
elif (.selection | type) != "object" then "open-pack receipt has no selection; the action requires one"
elif (.selection.selection_id | type) != "string" or .selection.selection_id == "" then
  "open-pack selection_id is \(.selection.selection_id | show); the action requires a non-empty string to key its content cache"
elif (.selection.cache_reused | type) != "boolean" then
  "open-pack cache_reused is \(.selection.cache_reused | show); the action requires a boolean"
elif (.selection.receipt | type) != "object" then "open-pack selection has no receipt; the action requires one"
elif (.selection.receipt.status | IN("qualified", "compatible") | not) then
  "selected receipt status is \(.selection.receipt.status | show); the action accepts qualified or compatible"
elif (.selection.receipt.releases | type) != "array" or (.selection.receipt.releases | length) == 0 then
  "selected receipt names no releases; the action requires the releases it scans with"
else
  .selection.receipt.releases[]
  | "\(.pack_id | show)@\(.release_version | show)" as $release
  | axes
  | if .integrity != "verified" then
      "selected release \($release) has \(.integrity | show) integrity; the action requires verified integrity"
    elif (.behavior | IN("qualified", "limited", "pending") | not) then
      "selected release \($release) has \(.behavior | show) behavior; the action accepts qualified, limited or pending"
    else empty end
end
'

environment_problems='
["BIFROST_OPEN_POLICY_PACK_ROOT", "BIFROST_SEMANTIC_PACK_CACHE_ROOT"] as $required
| ($required + ["BIFROST_OPEN_SEMANTIC_PACK_BUNDLE"]) as $allowed
| if type != "object" then "open-pack environment file is a JSON \(type); the action requires an object"
  elif ($required - keys) != [] then
    "open-pack environment file lacks \($required - keys | join(", ")); the action requires \($required | join(" and "))"
  elif (keys - $allowed) != [] then
    "open-pack environment file sets \(keys - $allowed | join(", ")); the action accepts only \($allowed | join(", "))"
  else
    to_entries[] | select((.value | type) != "string" or .value == "")
    | "open-pack environment value \(.key) is \(.value | show); the action requires a non-empty path"
  end
'

# Prints a ::error:: line for each problem the filter finds in a file. A file
# that is missing, empty or not exactly one JSON value is itself a problem.
problems() {
  local filter="$1" file="$2" label="$3"
  if [ ! -f "${file}" ]; then
    echo "::error::${label} ${file} is missing"
    return
  fi
  jq -rs --arg label "${label}" --arg file "${file}" "${defs}"'
    if length != 1 then "\($label) \($file) does not hold exactly one JSON value"
    else .[0] | '"${filter}"' end
    | "::error::" + command
  ' "${file}" 2>/dev/null || echo "::error::${label} ${file} is not valid JSON"
}

rejected="$(problems "${receipt_problems}" "${receipt}" "open-pack receipt"
  problems "${environment_problems}" "${env_file}" "open-pack environment file")"
if [ -n "${rejected}" ]; then
  echo "${rejected}"
  exit 1
fi

jq -c "${defs}"'
  {selection_id: .selection.selection_id,
   status: .selection.receipt.status,
   releases: [.selection.receipt.releases[] | {pack_id, release_version, role} + axes]}
' "${receipt}" > "${qualification}"

jq -r '
  "Open-pack selection \(.selection_id) is \(.status): "
  + ([.releases[] | "\(.pack_id)@\(.release_version) (integrity \(.integrity), behavior \(.behavior))"] | join(", "))
' "${qualification}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  jq -r '
    "### Bifrost open-pack selection", "",
    "Selection `\(.selection_id)` is **\(.status)**: "
    + if .status == "qualified" then
        "every release has verified integrity and qualified behavior."
      else
        "every release has verified integrity, but not every release has qualified behavior."
      end,
    "",
    "| Pack | Version | Role | Integrity | Behavior |",
    "| --- | --- | --- | --- | --- |",
    (.releases[] | "| `\(.pack_id)` | \(.release_version) | \(.role) | \(.integrity) | \(.behavior) |"),
    ""
  ' "${qualification}" >> "${GITHUB_STEP_SUMMARY}"
fi
