package com.acme;

public final class App {
    /**
     * The gateway is not resolvable in this workspace, so the effect set below
     * this marked procedure is open. The zero-cardinality claim becomes an
     * unmet obligation rather than a clean verdict.
     */
    @Pure
    void pureCallsAnUnresolvedTarget(Object gateway) {
        AcmeUnknownGateway.dispatch(gateway);
    }
}
