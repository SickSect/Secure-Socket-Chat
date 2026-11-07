package org.ugina.client;

import org.ugina.crypto.KeyFingerprint;

/**
 * Thrown when the server returns a different identity key for a peer than the
 * one this device pinned earlier. The new key is kept as a pending candidate
 * and is not used until the user explicitly trusts it with {@code /trust}.
 */
public class PeerKeyMismatchException extends Exception {

    private final String username;
    private final String expectedFingerprint;
    private final String actualFingerprint;

    public PeerKeyMismatchException(String username,
                                    String expectedFingerprint,
                                    String actualFingerprint) {
        super(message(username, expectedFingerprint, actualFingerprint));
        this.username = username;
        this.expectedFingerprint = expectedFingerprint;
        this.actualFingerprint = actualFingerprint;
    }

    public String getUsername() {
        return username;
    }

    public String getExpectedFingerprint() {
        return expectedFingerprint;
    }

    public String getActualFingerprint() {
        return actualFingerprint;
    }

    private static String message(String username,
                                  String expectedFingerprint,
                                  String actualFingerprint) {
        return "Identity key for '" + username + "' has changed. "
                + "Expected " + KeyFingerprint.format(expectedFingerprint)
                + ", but the server offered " + KeyFingerprint.format(actualFingerprint)
                + ". Verify the new fingerprint with " + username
                + " out of band, then run: /trust " + username + " "
                + KeyFingerprint.shortForm(actualFingerprint);
    }
}
