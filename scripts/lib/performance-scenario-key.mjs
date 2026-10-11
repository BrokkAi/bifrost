export function scenarioIdentity(repo, scenario, caseId, transport) {
  return [repo, scenario, caseId ?? null, transport];
}

export function scenarioPathKey(identity) {
  const [repo, scenario, caseId, transport] = identity;
  return `${repo}/${scenario}/${caseId ?? "-"}/${transport}`;
}
