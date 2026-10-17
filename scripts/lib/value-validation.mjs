const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/u;

export function isRecordObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function requireValue(value, message) {
  if (!value) {
    throw new Error(message);
  }
  return value;
}

export function requireNonEmptyString(value, message) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(message);
  }
  return value;
}

export function isFullCommitSha(value) {
  return typeof value === "string" && FULL_COMMIT_SHA.test(value);
}
