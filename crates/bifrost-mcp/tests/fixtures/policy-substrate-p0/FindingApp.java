package com.acme;

public final class App {
    /** Direct: depth 1, classification `direct`. A finding. */
    @Pure
    void pureCallsTheApiDirectly(AcmeHttpClient client) {
        client.send("https://example.test");
    }

    /** Transitive: depth 2, classification `transitive`. A finding. */
    @Pure
    void pureCallsTheApiThroughAHelper(AcmeHttpClient client) {
        relay(client);
    }

    static void relay(AcmeHttpClient client) {
        client.send("https://example.test");
    }

    /** The same helper, no marker. The policy joins on the marker, so no finding. */
    void unannotatedCallsTheHelper(AcmeHttpClient client) {
        relay(client);
    }

    /** A marked procedure whose whole reachable call graph is analyzed and clean. */
    @Pure
    void pureCallsAProvenCleanHelper() {
        leaf();
    }

    static void leaf() {
    }
}
