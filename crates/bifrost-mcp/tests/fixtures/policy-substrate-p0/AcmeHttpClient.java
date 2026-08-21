package com.acme;

/**
 * The exact API the workspace semantic model annotates with the namespaced
 * effect `acme.network_io`.
 */
public final class AcmeHttpClient {
    /** Declared with timing `immediate`. */
    public String send(String url) {
        return url;
    }

    /** Declared with timing `deferred`. */
    public String sendLater(String url) {
        return url;
    }
}
