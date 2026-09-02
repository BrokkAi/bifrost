class LedgerStore {
  commit(entry: string) {}
}

class AuditStore {
  commit(entry: string) {}
}

function openLedger() {
  return new LedgerStore();
}

export function record(useAudit: boolean) {
  const either = useAudit ? new AuditStore() : new LedgerStore();
  either.commit("either");

  const ledger = new LedgerStore();
  ledger.commit("direct");

  const opened = openLedger();
  opened.commit("factory");
}
